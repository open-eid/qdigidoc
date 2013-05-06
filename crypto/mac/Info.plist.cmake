<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>English</string>
	<key>CFBundleExecutable</key>
	<string>${MACOSX_BUNDLE_EXECUTABLE_NAME}</string>
	<key>CFBundleIconFile</key>
	<string>${MACOSX_BUNDLE_ICON_FILE}</string>
	<key>CFBundleIdentifier</key>
	<string>${MACOSX_BUNDLE_GUI_IDENTIFIER}</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>${MACOSX_BUNDLE_BUNDLE_NAME}</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>${MACOSX_BUNDLE_SHORT_VERSION_STRING}</string>
	<key>CFBundleVersion</key>
	<string>${MACOSX_BUNDLE_BUNDLE_VERSION}</string>
	<key>NSHumanReadableCopyright</key>
	<string>${MACOSX_BUNDLE_COPYRIGHT}</string>
	<key>NSPrincipalClass</key>
	<string>NSApplication</string>
	<key>NSHighResolutionCapable</key>
	<true/>
	<key>LSHasLocalizedDisplayName</key>
	<true/>
	<key>LSApplicationCategoryType</key>
	<string>public.app-category.productivity</string>
	<key>LSMinimumSystemVersion</key>
	<string>10.6.0</string>
	<key>CFBundleDocumentTypes</key>
	<array>
		<dict>
			<key>CFBundleTypeExtensions</key>
			<array>
				<string>cdoc</string>
			</array>
			<key>CFBundleTypeIconFile</key>
			<string>cdoc.icns</string>
			<key>CFBundleTypeMIMETypes</key>
			<array>
				<string>application/x-cdoc</string>
			</array>
			<key>CFBundleTypeName</key>
			<string>CDoc - xml crypto format</string>
			<key>CFBundleTypeRole</key>
			<string>Editor</string>
			<key>LSHandlerRank</key>
			<string>Owner</string>
			<key>LSItemContentTypes</key>
			<array>
				<string>ee.ria.cdoc</string>
			</array>
		</dict>
		<dict>
			<key>CFBundleTypeName</key>
			<string>All files</string>
			<key>CFBundleTypeOSTypes</key>
			<array>
				<string>****</string>
			</array>
			<key>CFBundleTypeRole</key>
			<string>Viewer</string>
		</dict>
	</array>
	<key>NSServices</key>
	<array>
		<dict>
			<key>NSMenuItem</key>
			<dict>
				<key>default</key>
				<string>Encrypt with DigiDoc3 Crypto</string>
			</dict>
			<key>NSMessage</key>
			<string>openFile</string>
			<key>NSPortName</key>
			<string>${MACOSX_BUNDLE_EXECUTABLE_NAME}</string>
			<key>NSRequiredContext</key>
			<dict>
				<key>NSTextContent</key>
				<string>FilePath</string>
			</dict>
			<key>NSSendTypes</key>
			<array>
				<string>public.url</string>
			</array>
		</dict>
	</array>
	<key>UTExportedTypeDeclarations</key>
	<array>
		<dict>
			<key>UTTypeConformsTo</key>
			<array>
				<string>public.xml</string>
				<string>public.data</string>
			</array>
			<key>UTTypeDescription</key>
			<string>CDoc - xml crypto format</string>
			<key>UTTypeIconFile</key>
			<string>cdoc.icns</string>
			<key>UTTypeIdentifier</key>
			<string>ee.ria.cdoc</string>
			<key>UTTypeTagSpecification</key>
			<dict>
				<key>com.apple.ostype</key>
				<string>CDOC</string>
				<key>public.filename-extension</key>
				<string>cdoc</string>
				<key>public.mime-type</key>
				<array>
					<string>application/x-cdoc</string>
				</array>
			</dict>
		</dict>
	</array>
</dict>
</plist>
