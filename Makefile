IDENTITY ?= Developer ID Application: Nazar Voitovych (37A7P47GPA)
CLI_ID   := dev.nvlab.sx.cli
BUILD    := build
VERSION  := $(shell sed -n 's/.*version = "\(.*\)"/\1/p' Sources/SxCore/Constants.swift)
DMG      := $(BUILD)/sx-$(VERSION).dmg
APP      := $(BUILD)/export/Sx.app

.PHONY: test icons cli app dmg dmg-only release publish install uninstall clean

test:
	swift test

# Brand assets (app icon, menu bar template, DMG background, site favicons) from code.
icons:
	swift design/render.swift design/out
	rm -rf App/Sources/Assets.xcassets/AppIcon.appiconset
	cp -R design/out/AppIcon.appiconset App/Sources/Assets.xcassets/
	cp design/out/MenuIcon.png design/out/MenuIcon@2x.png App/Sources/Assets.xcassets/MenuIcon.imageset/

# CLI: universal release build, signed so the broker accepts it (identifier + team are checked).
cli:
	swift build -c release --arch arm64 --arch x86_64
	mkdir -p $(BUILD)
	cp .build/apple/Products/Release/sx $(BUILD)/sx
	codesign --force --sign "$(IDENTITY)" --identifier $(CLI_ID) --options runtime --timestamp $(BUILD)/sx

# App: Developer ID export (Xcode creates/renews the profile via the signed-in account), CLI embedded.
app: cli
	cd App && xcodegen generate --quiet
	rm -rf $(BUILD)/Sx.xcarchive $(BUILD)/export
	xcodebuild -project App/Sx.xcodeproj -scheme Sx -configuration Release \
	  -archivePath $(BUILD)/Sx.xcarchive -allowProvisioningUpdates -quiet archive
	xcodebuild -exportArchive -archivePath $(BUILD)/Sx.xcarchive \
	  -exportOptionsPlist App/ExportOptions.plist -exportPath $(BUILD)/export -allowProvisioningUpdates -quiet
	codesign -dv $(APP)/Contents/Helpers/sx 2>&1 | grep -q 'Identifier=$(CLI_ID)'

# Installer: drag-to-Applications DMG with background, signed.
dmg: app dmg-only

dmg-only:
	tiffutil -cathidpicheck design/out/dmg-background.png design/out/dmg-background@2x.png -out $(BUILD)/dmg-bg.tiff
	rm -f $(DMG)
	uvx --from dmgbuild dmgbuild -s scripts/dmg-settings.py -D app=$(APP) -D bg=$(BUILD)/dmg-bg.tiff "sx $(VERSION)" $(DMG)
	codesign --force --sign "$(IDENTITY)" --timestamp $(DMG)
	@echo "→ $(DMG)"

# Notarized release: Xcode uploads the archive with the signed-in account (no API key needed),
# waits for Apple, exports the stapled app, then builds and signs the DMG from it.
release: cli
	cd App && xcodegen generate --quiet
	rm -rf $(BUILD)/Sx.xcarchive $(BUILD)/export $(BUILD)/notarized
	xcodebuild -project App/Sx.xcodeproj -scheme Sx -configuration Release \
	  -archivePath $(BUILD)/Sx.xcarchive -allowProvisioningUpdates -quiet archive
	xcodebuild -exportArchive -archivePath $(BUILD)/Sx.xcarchive \
	  -exportOptionsPlist App/ExportOptions-notarize.plist -exportPath $(BUILD)/notarized -allowProvisioningUpdates
	scripts/wait-notarized.sh $(BUILD)/Sx.xcarchive $(BUILD)/export
	xcrun stapler validate $(APP)
	$(MAKE) dmg-only

# Public download: R2 bucket nvlab-static → static.nvlab.co/sx/ (nvlab.co/downloads/sx/ redirects there).
# Refuses un-notarized builds: Gatekeeper would block them for every user.
publish:
	xcrun stapler validate $(APP)
	spctl -a -t open --context context:primary-signature -v $(DMG)
	shasum -a 256 $(DMG) | awk '{print $$1}' > $(DMG).sha256
	wrangler r2 object put nvlab-static/sx/sx-$(VERSION).dmg --file=$(DMG) \
	  --content-type=application/x-apple-diskimage --cache-control "public, max-age=300" --remote
	wrangler r2 object put nvlab-static/sx/sx-macos.dmg --file=$(DMG) \
	  --content-type=application/x-apple-diskimage --cache-control "public, max-age=300" --remote
	wrangler r2 object put nvlab-static/sx/sx-macos.dmg.sha256 --file=$(DMG).sha256 --content-type=text/plain --remote

install: app
	-osascript -e 'quit app id "dev.nvlab.sx"' 2>/dev/null
	rm -rf /Applications/Sx.app
	ditto $(APP) /Applications/Sx.app
	ln -sf /Applications/Sx.app/Contents/Helpers/sx $(HOME)/.local/bin/sx
	open /Applications/Sx.app

uninstall:
	-osascript -e 'quit app id "dev.nvlab.sx"' 2>/dev/null
	rm -rf /Applications/Sx.app $(HOME)/.local/bin/sx

clean:
	rm -rf $(BUILD) .build App/Sx.xcodeproj
