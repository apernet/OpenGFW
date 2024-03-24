{
  lib,
  pkgs,
}:
pkgs.buildGoApplication rec {
  pname = "opengfw";
  version = "0.1.1";
  pwd = ../.;
  src = ../.;
  
  buildPhase = ''
    go build
  '';

  installPhase = ''
    mkdir -p $out/bin
    cp OpenGFW $out/bin
  '';
    
  meta = with lib; {
    description = "A flexible, easy-to-use, open source implementation of GFW on Linux.";
    longDescription = ''
      OpenGFW is a flexible, easy-to-use, open source implementation of GFW on Linux
      that's in many ways more powerful than the real thing.
      It's cyber sovereignty you can have on a home router.
    '';
    homepage = "https://github.com/apernet/OpenGFW";
    license = licenses.mpl20;
    mainProgram = "OpenGFW";
    platforms = [ "x86_64-linux" "aarch64-linux" ];
  };
}
