{ pkgs ? import <nixpkgs> {} }:

pkgs.buildGoPackage rec {
  pname = "kube-router";
  version = "0.2.5";

  goPackagePath = "github.com/cloudnativelabs/kube-router";

  src = ./.;

  ldflags = [
    "-X ${goPackagePath}/pkg/cmd.version=${version}"
    "-X ${goPackagePath}/pkg/cmd.buildDate=Nix"
  ];

  meta = with pkgs.lib; {
    homepage = "https://www.kube-router.io/";
    description = "All-in-one router, firewall and service proxy for Kubernetes";
    license = licenses.asl20;
    maintainers = with maintainers; [ colemickens johanot ];
    platforms = platforms.linux;
  };
}
