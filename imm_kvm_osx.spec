# -*- mode: python -*-

block_cipher = None


a = Analysis(['imm_kvm/__init__.py'],
             pathex=['imm_kvm'],
			 binaries=[
			      ('/System/Library/Frameworks/Tk.framework/Tk', 'tk'),
			      ('/System/Library/Frameworks/Tcl.framework/Tcl', 'tcl')],
             datas=[('imm_kvm/osx-jre', 'osx-jre') ('imm_kvm/ibm-systemx', 'ibm-systemx')],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          [],
          exclude_binaries=True,
          name='imm_kvm',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          console=True )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               name='IMM KVM OSX')
app = BUNDLE(exe,
        name='IMM KVM.app',
        icon=None,
        bundle_identifier=None,
		info_plist={
		    'NSHighResolutionCapable': 'True'
		    },)
