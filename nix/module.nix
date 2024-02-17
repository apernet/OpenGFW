packages: {
  lib,
  pkgs,
  config,
  ...
}: let
  inherit (lib) mkOption types mkIf;
  cfg = config.services.opengfw;

  settings =
    if cfg.settings != {}
    then (pkgs.formats.yaml {}).generate "OpenGFW-Config.yaml" cfg.settings
    else cfg.settingsFile;
  rules =
    if cfg.rules != []
    then (pkgs.formats.yaml {}).generate "OpenGFW-Rules.yaml" cfg.rules
    else cfg.rulesFile;
in {
  options.services.opengfw = {
    enable = lib.mkEnableOption (lib.mdDoc "A flexible, easy-to-use, open source implementation of GFW on Linux.");

    package = lib.mkPackageOption packages.${pkgs.system} "opengfw" {
      default = "opengfw";
    };

    user = mkOption {
      default = "opengfw";
      type = types.singleLineStr;
    };

    dir = mkOption {
      default = "/var/lib/opengfw";
      type = types.singleLineStr;
    };

    rulesFile = mkOption {
      default = null;
      type = types.nullOr types.path;
    };

    settingsFile = mkOption {
      default = null;
      type = types.nullOr types.path;
    };

    settings = mkOption {
      default = {};
      type = types.attrs;
      example = {
        io = {
          queueSize = 1024;
          local = true;
        };

        workers = {
          count = 4;
          queueSize = 16;
          tcpMaxBufferedPagesTotal = 4096;
          tcpMaxBufferedPagesPerConn = 64;
          udpMaxStreams = 4096;
        };
      };
    };

    rules = mkOption {
      default = [];
      type = types.listOf types.attrs;
      description = ''
        OpenGFW supports the actions 'allow', 'block', 'drop' and 'modify'
        as listed on https://github.com/apernet/OpenGFW?tab=readme-ov-file#supported-actions.
        It uses Expr Language (https://expr-lang.org/docs/language-definition).
        Properties of the analyzers are documented here: https://github.com/apernet/OpenGFW/blob/master/docs/Analyzers.md.
      '';
      example = [
        {
          name = "block v2ex http";
          action = "block";
          expr = ''string(http?.req?.headers?.host) endsWith "v2ex.com"'';
        }
        {
          name = "block google socks";
          action = "block";
          expr = ''string(socks?.req?.addr) endsWith "google.com" && socks?.req?.port == 80'';
        }
        {
          name = "v2ex dns poisoning";
          action = "modify";
          modifier = {
            name = "dns";
            args = {
              a = "0.0.0.0";
              aaaa = "::";
            };
          };
          expr = ''dns != nil && dns.qr && any(dns.questions, {.name endsWith "v2ex.com"})'';
        }
      ];
    };
  };

  config = mkIf cfg.enable {
    security.wrappers.OpenGFW = {
      owner = cfg.user;
      group = cfg.user;
      capabilities = "cap_net_admin+ep";
      source = "${cfg.package}/bin/OpenGFW";
    };

    systemd = {
      services.opengfw = let
        cu = "${pkgs.coreutils}/bin";
      in {
        description = "OpenGFW";
        wantedBy = ["multi-user.target"];
        after = ["network.target"];
        environment.PATH = lib.mkForce "${cu}:${pkgs.iptables}/bin";
        preStart = mkIf ((cfg.rules != [] && cfg.settings != {}) || (cfg.rulesFile != null && cfg.settingsFile != null)) ''
          ${cu}/ln -sf ${settings} config.yaml
          ${cu}/ln -sf ${rules} rules.yaml
        '';

        serviceConfig = {
          WorkingDirectory = cfg.dir;
          ExecStart = "${config.security.wrapperDir}/OpenGFW -c config.yaml rules.yaml";
          ExecReload = "${cu}/kill -HUP $MAINPID";
          Restart = "always";
          User = cfg.user;
        };
      };

      tmpfiles.rules = [
        "d '${cfg.dir}'        0660 ${cfg.user} ${cfg.user} - -"
      ];
    };

    users = {
      users.${cfg.user} = {
        description = "opengfw user";
        isNormalUser = true;
        group = cfg.user;
        home = cfg.dir;
      };

      groups.${cfg.user} = {};
    };
  };
}
