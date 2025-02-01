package tcp

import (
    "bytes"
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "sync"
    "time"

    "github.com/apernet/OpenGFW/analyzer"
)

var _ analyzer.TCPAnalyzer = (*TrojanAnalyzer)(nil)

// Configuration constants that can be set via expr
var (
    PositiveScore   = 2  // Score increase for positive detection
    NegativeScore   = 1  // Score decrease for negative detection
    BlockThreshold  = 20 // Threshold for blocking
)

// Fixed configuration
const (
    ResultFile = "trojan_result.json"
    BlockFile  = "trojan_block.json"
    BasePath   = "/var/log/opengfw" // Base path for log files
)

// CCS stands for "Change Cipher Spec"
var ccsPattern = []byte{20, 3, 3, 0, 1, 1}

// IPStats represents the statistics for a single IP
type IPStats struct {
    IP        string    `json:"ip"`
    Score     int       `json:"score"`
    FirstSeen time.Time `json:"first_seen"`
    LastSeen  time.Time `json:"last_seen"`
}

// TrojanResults holds all IP statistics
type TrojanResults struct {
    IPList []IPStats `json:"ip_list"`
    mu     sync.Mutex
}

// Global variables
var (
    results     *TrojanResults
    blockedIPs  map[string]struct{}
    resultMutex sync.RWMutex
    initialized bool
)

// TrojanAnalyzer implements the TCP analyzer interface
type TrojanAnalyzer struct{}

func (a *TrojanAnalyzer) Name() string {
    return "trojan"
}

func (a *TrojanAnalyzer) Limit() int {
    return 512000
}

// Initialize the statistics system
func initTrojanStats() error {
    if initialized {
        return nil
    }
    resultMutex.Lock()
    defer resultMutex.Unlock()

    if initialized {
        return nil
    }

    // Create base directory if it doesn't exist
    if err := os.MkdirAll(BasePath, 0755); err != nil {
        return fmt.Errorf("failed to create base directory: %w", err)
    }

    results = &TrojanResults{
        IPList: make([]IPStats, 0),
    }
    blockedIPs = make(map[string]struct{})

    // Load existing results
    resultPath := filepath.Join(BasePath, ResultFile)
    if data, err := os.ReadFile(resultPath); err == nil {
        if err := json.Unmarshal(data, &results.IPList); err != nil {
            return fmt.Errorf("failed to unmarshal results: %w", err)
        }
    }

    // Load blocked IPs
    blockPath := filepath.Join(BasePath, BlockFile)
    if data, err := os.ReadFile(blockPath); err == nil {
        var blockedList []string
        if err := json.Unmarshal(data, &blockedList); err != nil {
            return fmt.Errorf("failed to unmarshal blocked IPs: %w", err)
        }
        for _, ip := range blockedList {
            blockedIPs[ip] = struct{}{}
        }
    }

    initialized = true
    return nil
}

// Update IP statistics
func updateIPStats(ip string, isPositive bool) error {
    if err := initTrojanStats(); err != nil {
        return err
    }

    results.mu.Lock()
    defer results.mu.Unlock()

    // Check if IP is already blocked
    if _, blocked := blockedIPs[ip]; blocked {
        return nil
    }

    now := time.Now()
    var found bool

    // Update existing IP stats
    for i := range results.IPList {
        if results.IPList[i].IP == ip {
            if isPositive {
                results.IPList[i].Score += PositiveScore
            } else {
                results.IPList[i].Score = max(0, results.IPList[i].Score-NegativeScore)
            }
            results.IPList[i].LastSeen = now
            found = true

            // Check if score exceeds threshold
            if results.IPList[i].Score >= BlockThreshold {
                if err := addToBlockList(ip); err != nil {
                    return fmt.Errorf("failed to add IP to block list: %w", err)
                }
            }
            break
        }
    }

    // Add new IP if not found
    if !found && isPositive {
        results.IPList = append(results.IPList, IPStats{
            IP:        ip,
            Score:     PositiveScore,
            FirstSeen: now,
            LastSeen:  now,
        })
    }

    return saveResults()
}

// Add IP to block list
func addToBlockList(ip string) error {
    blockedIPs[ip] = struct{}{}

    blockPath := filepath.Join(BasePath, BlockFile)
    var blockedList []string

    // Read existing block list
    if data, err := os.ReadFile(blockPath); err == nil {
        if err := json.Unmarshal(data, &blockedList); err != nil {
            return fmt.Errorf("failed to unmarshal blocked IPs: %w", err)
        }
    }

    // Add new IP if not already in list
    if !contains(blockedList, ip) {
        blockedList = append(blockedList, ip)
    }

    // Save updated block list
    data, err := json.MarshalIndent(blockedList, "", "  ")
    if err != nil {
        return fmt.Errorf("failed to marshal blocked IPs: %w", err)
    }

    if err := os.WriteFile(blockPath, data, 0644); err != nil {
        return fmt.Errorf("failed to write block file: %w", err)
    }

    return nil
}

// Save results to file
func saveResults() error {
    data, err := json.MarshalIndent(results.IPList, "", "  ")
    if err != nil {
        return fmt.Errorf("failed to marshal results: %w", err)
    }

    resultPath := filepath.Join(BasePath, ResultFile)
    if err := os.WriteFile(resultPath, data, 0644); err != nil {
        return fmt.Errorf("failed to write results file: %w", err)
    }

    return nil
}

// Helper functions
func contains(slice []string, item string) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}

func max(a, b int) int {
    if a > b {
        return a
    }
    return b
}

// trojanStream represents a TCP stream being analyzed
type trojanStream struct {
    logger   analyzer.Logger
    info     analyzer.TCPInfo
    first    bool
    count    bool
    rev      bool
    seq      [4]int
    seqIndex int
}

// NewTCP creates a new TCP stream analyzer
func (a *TrojanAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
    return &trojanStream{
        logger: logger,
        info:   info,
        first:  true,
    }
}

// Feed processes incoming TCP data
func (s *trojanStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, done bool) {
    if skip != 0 {
        return nil, true
    }
    if len(data) == 0 {
        return nil, false
    }

    if s.first {
        s.first = false
        if !(!rev && len(data) >= 3 && data[0] >= 0x16 && data[0] <= 0x17 &&
            data[1] == 0x03 && data[2] <= 0x09) {
            return nil, true
        }
    }

    if !rev && !s.count && len(data) >= 6 && bytes.Equal(data[:6], ccsPattern) {
        s.count = true
    }

    if s.count {
        if rev == s.rev {
            s.seq[s.seqIndex] += len(data)
        } else {
            s.seqIndex++
            if s.seqIndex == 4 {
                isTrojan := isTrojanSeq(s.seq)
                dstIP := s.info.DstIP.String()

                // Check if IP is blocked
                _, blocked := blockedIPs[dstIP]
                if blocked {
                    isTrojan = true
                } else {
                    // Update statistics
                    if err := updateIPStats(dstIP, isTrojan); err != nil {
                        // Use appropriate logger method
                        s.logger.Errorf("Failed to update IP stats: %v", err)
                    }
                }

                return &analyzer.PropUpdate{
                    Type: analyzer.PropUpdateReplace,
                    M: analyzer.PropMap{
                        "seq": s.seq,
                        "yes": isTrojan,
                    },
                }, true
            }
            s.seq[s.seqIndex] += len(data)
            s.rev = rev
        }
    }

    return nil, false
}

func (s *trojanStream) Close(limited bool) *analyzer.PropUpdate {
    return nil
}

func isTrojanSeq(seq [4]int) bool {
	length1 := seq[0]
	length2 := seq[1]
	length3 := seq[2]
	length4 := seq[3]

	if length2 <= 2431 {
		if length2 <= 157 {
			if length1 <= 156 {
				if length3 <= 108 {
					return false
				} else {
					return false
				}
			} else {
				if length1 <= 892 {
					if length3 <= 40 {
						return false
					} else {
						if length3 <= 788 {
							if length4 <= 185 {
								if length1 <= 411 {
									return true
								} else {
									return false
								}
							} else {
								if length2 <= 112 {
									return false
								} else {
									return true
								}
							}
						} else {
							if length3 <= 1346 {
								if length1 <= 418 {
									return false
								} else {
									return true
								}
							} else {
								return false
							}
						}
					}
				} else {
					if length2 <= 120 {
						if length2 <= 63 {
							return false
						} else {
							if length4 <= 653 {
								return false
							} else {
								return false
							}
						}
					} else {
						return false
					}
				}
			}
		} else {
			if length1 <= 206 {
				if length1 <= 185 {
					if length1 <= 171 {
						return false
					} else {
						if length4 <= 211 {
							return false
						} else {
							return false
						}
					}
				} else {
					if length2 <= 251 {
						return true
					} else {
						return false
					}
				}
			} else {
				if length2 <= 286 {
					if length1 <= 1123 {
						if length3 <= 70 {
							return false
						} else {
							if length1 <= 659 {
								if length3 <= 370 {
									return true
								} else {
									return false
								}
							} else {
								if length4 <= 272 {
									return false
								} else {
									return true
								}
							}
						}
					} else {
						if length4 <= 537 {
							if length2 <= 276 {
								if length3 <= 1877 {
									return false
								} else {
									return false
								}
							} else {
								return false
							}
						} else {
							if length1 <= 1466 {
								if length1 <= 1435 {
									return false
								} else {
									return true
								}
							} else {
								if length2 <= 193 {
									return false
								} else {
									return false
								}
							}
						}
					}
				} else {
					if length1 <= 284 {
						if length1 <= 277 {
							if length2 <= 726 {
								return false
							} else {
								if length2 <= 768 {
									return true
								} else {
									return false
								}
							}
						} else {
							if length2 <= 782 {
								if length4 <= 783 {
									return true
								} else {
									return false
								}
							} else {
								return false
							}
						}
					} else {
						if length2 <= 492 {
							if length2 <= 396 {
								if length2 <= 322 {
									return false
								} else {
									return false
								}
							} else {
								if length4 <= 971 {
									return false
								} else {
									return true
								}
							}
						} else {
							if length2 <= 2128 {
								if length2 <= 1418 {
									return false
								} else {
									return false
								}
							} else {
								if length3 <= 103 {
									return false
								} else {
									return false
								}
							}
						}
					}
				}
			}
		}
	} else {
		if length2 <= 6232 {
			if length3 <= 85 {
				if length2 <= 3599 {
					return false
				} else {
					if length1 <= 613 {
						return false
					} else {
						return false
					}
				}
			} else {
				if length3 <= 220 {
					if length4 <= 1173 {
						if length1 <= 874 {
							if length4 <= 337 {
								if length4 <= 68 {
									return true
								} else {
									return true
								}
							} else {
								if length1 <= 667 {
									return true
								} else {
									return true
								}
							}
						} else {
							if length3 <= 108 {
								if length1 <= 1930 {
									return true
								} else {
									return true
								}
							} else {
								if length2 <= 5383 {
									return false
								} else {
									return true
								}
							}
						}
					} else {
						return false
					}
				} else {
					if length1 <= 664 {
						if length3 <= 411 {
							if length3 <= 383 {
								if length4 <= 346 {
									return true
								} else {
									return false
								}
							} else {
								if length1 <= 445 {
									return true
								} else {
									return false
								}
							}
						} else {
							if length2 <= 3708 {
								if length4 <= 307 {
									return true
								} else {
									return false
								}
							} else {
								if length2 <= 4656 {
									return false
								} else {
									return false
								}
							}
						}
					} else {
						if length1 <= 1055 {
							if length3 <= 580 {
								if length1 <= 724 {
									return true
								} else {
									return false
								}
							} else {
								if length1 <= 678 {
									return false
								} else {
									return true
								}
							}
						} else {
							if length2 <= 5352 {
								if length3 <= 1586 {
									return false
								} else {
									return false
								}
							} else {
								if length4 <= 2173 {
									return true
								} else {
									return false
								}
							}
						}
					}
				}
			}
		} else {
			if length2 <= 9408 {
				if length1 <= 670 {
					if length4 <= 76 {
						if length3 <= 175 {
							return true
						} else {
							return true
						}
					} else {
						if length2 <= 9072 {
							if length3 <= 314 {
								if length3 <= 179 {
									return false
								} else {
									return false
								}
							} else {
								if length4 <= 708 {
									return false
								} else {
									return false
								}
							}
						} else {
							return true
						}
					}
				} else {
					if length1 <= 795 {
						if length2 <= 6334 {
							if length2 <= 6288 {
								return true
							} else {
								return false
							}
						} else {
							if length4 <= 6404 {
								if length2 <= 8194 {
									return true
								} else {
									return true
								}
							} else {
								if length2 <= 8924 {
									return false
								} else {
									return true
								}
							}
						}
					} else {
						if length3 <= 732 {
							if length1 <= 1397 {
								if length3 <= 179 {
									return false
								} else {
									return false
								}
							} else {
								if length1 <= 1976 {
									return false
								} else {
									return false
								}
							}
						} else {
							if length1 <= 2840 {
								if length1 <= 2591 {
									return false
								} else {
									return true
								}
							} else {
								return false
							}
						}
					}
				}
			} else {
				if length4 <= 30 {
					return false
				} else {
					if length2 <= 13314 {
						if length4 <= 1786 {
							if length2 <= 13018 {
								if length4 <= 869 {
									return false
								} else {
									return false
								}
							} else {
								return true
							}
						} else {
							if length3 <= 775 {
								return false
							} else {
								return false
							}
						}
					} else {
						if length4 <= 73 {
							return false
						} else {
							if length3 <= 640 {
								if length3 <= 237 {
									return false
								} else {
									return false
								}
							} else {
								if length2 <= 43804 {
									return false
								} else {
									return false
								}
							}
						}
					}
				}
			}
		}
	}
}
