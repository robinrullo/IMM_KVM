echo "Marking Execute bit on Java JRE binary"
chmod +x imm_kvm/osx-jre/bin/java
echo "Building Package using PyInstaller"
python3 -m PyInstaller ./imm_kvm_osx.spec --onefile --windowed
echo "Copying rest of JRE, JARs and libs to .app file"
cp -R dist/imm_kvm\ OSX/* dist/imm_kvm\ OSX.app/Contents/MacOS/
