# dmgbuild settings: `dmgbuild -s scripts/dmg-settings.py -D app=build/export/Sx.app -D bg=build/dmg-bg.tiff "sx" out.dmg`
import os.path

app = defines["app"]
format = "UDZO"
filesystem = "APFS"
files = [app]
symlinks = {"Applications": "/Applications"}
icon_locations = {os.path.basename(app): (165, 190), "Applications": (495, 190)}
background = defines["bg"]
window_rect = ((200, 120), (660, 400))
icon_size = 112
text_size = 13
show_status_bar = False
show_tab_view = False
show_toolbar = False
show_pathbar = False
show_sidebar = False
default_view = "icon-view"
hide_extensions = [os.path.basename(app)]
