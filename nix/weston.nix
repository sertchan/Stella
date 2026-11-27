{pkgs}:
(pkgs.weston.override {
  xwaylandSupport = false;
  rdpSupport = false;
  vncSupport = false;
  remotingSupport = false;
  pipewireSupport = false;
  demoSupport = false;
  luaSupport = false;
  pangoSupport = false;
  jpegSupport = false;
  webpSupport = false;
  lcmsSupport = false;
}).overrideAttrs (old: {
  pname = "weston-headless";
  mesonFlags =
    (old.mesonFlags or [])
    ++ [
      "-Dbackend-default=headless"
      "-Dbackend-drm=false"
      "-Dbackend-wayland=false"
      "-Dbackend-x11=false"
      "-Drenderer-gl=false"
      "-Dshell-desktop=false"
      "-Dshell-ivi=false"
      "-Dshell-lua=false"
      "-Ddemo-clients=false"
      "-Dsimple-clients="
      "-Dtools="
      "-Dimage-jpeg=false"
      "-Dimage-webp=false"
      "-Dcolor-management-lcms=false"
    ];
})
