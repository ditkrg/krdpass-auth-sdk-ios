Pod::Spec.new do |s|
  s.name             = 'KrdpassAuth'
  s.version          = '1.6.0'
  s.summary          = 'Official KRDPASS Authentication SDK for iOS'
  s.description      = <<-DESC
  KRDPASS Auth SDK for iOS. Handles app-to-app OAuth sign-in, deep link callbacks,
  and secure state validation.
  DESC

  s.homepage         = 'https://github.com/ditkrg/krdpass-auth-sdk-ios'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'KRDPASS Team' => 'integration@pass.krd' }
  # :tag tracks s.version because CocoaPods resolves a released version to its tag, so this
  # line has to stay a tag. Be aware of what that means: a git tag is mutable, and Pods'
  # SPEC CHECKSUMS hashes this podspec text and not the source it points at, so moving a
  # released tag onto a different commit is invisible to everyone who already resolved it.
  # If you need tamper-evidence, pin the commit in your own Podfile instead:
  #   pod 'KrdpassAuth', :git => 'https://github.com/ditkrg/krdpass-auth-sdk-ios.git',
  #                      :commit => '<full 40-char sha>'
  s.source           = { :git => 'https://github.com/ditkrg/krdpass-auth-sdk-ios.git', :tag => "v#{s.version}" }

  s.ios.deployment_target = '15.0'
  s.swift_version = '6.0'

  s.source_files = 'Sources/KrdpassAuth/**/*.swift'

  # Privacy manifest, in the bundle Apple looks for it in. SPM ships the same file as a target
  # resource, so both install paths declare identical privacy behaviour.
  s.resource_bundles = { 'KrdpassAuth' => ['Sources/KrdpassAuth/PrivacyInfo.xcprivacy'] }

  # CryptoKit (PKCE SHA-256), Security (JWT/JWKS RSA verification) and SwiftUI (the
  # withKrdpassDeepLinkHandling view modifier) are imported directly; SPM auto-links them from
  # `import`, but CocoaPods needs them declared or a consumer fails to link.
  s.frameworks = 'UIKit', 'Foundation', 'CryptoKit', 'Security', 'SwiftUI'
end
