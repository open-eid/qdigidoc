# DigiDoc3 Client

 * License: LGPL 2.1
 * &copy; Estonian Information System Authority
 * [Architecture of ID-software](http://open-eid.github.io)

## Building
[![Build Status](https://travis-ci.org/open-eid/qdigidoc.svg?branch=master)](https://travis-ci.org/open-eid/qdigidoc)
[![Build Status](https://ci.appveyor.com/api/projects/status/github/open-eid/qdigidoc?branch=master&svg=true)](https://ci.appveyor.com/project/open-eid/qdigidoc)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/725/badge.svg)](https://scan.coverity.com/projects/725)

### Ubuntu

1. Install dependencies

        sudo apt-get install cmake qttools5-dev qttools5-dev-tools libpcsclite-dev libssl-dev libdigidocpp-dev

2. Fetch the source

        git clone --recursive https://github.com/open-eid/qdigidoc
        cd qdigidoc

3. Configure

        mkdir build
        cd build
        cmake ..

4. Build

        make

5. Install

        sudo make install

6. Execute

        /usr/local/bin/qdigidocclient
        
### OSX

1. Install dependencies from
   * [XCode](https://itunes.apple.com/en/app/xcode/id497799835?mt=12)
   * [http://www.cmake.org](http://www.cmake.org)
   * [http://qt-project.org](http://qt-project.org)
   * [libdigidocpp-*.pkg](https://installer.id.ee/media/osx/)
2. Fetch the source

        git clone --recursive https://github.com/open-eid/qdigidoc
        cd qdigidoc

3. Configure

        mkdir build
        cd build
        cmake -DQTSDK="~/Qt/5.3/clang_64" ..

4. Build

        make

5. Install

        sudo make install

6. Execute

        open /usr/local/bin/qdigidocclient.app

### Windows

1. Install dependencies from
    * [Visual Studio Express 2013 for Windows Desktop](http://www.visualstudio.com/en-us/products/visual-studio-express-vs.aspx)
	* [http://www.cmake.org](http://www.cmake.org)
	* [http://qt-project.org](http://qt-project.org)
	* [Eesti_ID_kaart-CPP-teek-arendajale-*.msi](https://installer.id.ee/media/win/)
2. Fetch the source

        git clone --recursive https://github.com/open-eid/qdigidoc
        cd qdigidoc

3. Configure

        mkdir build
        cd build
        cmake -G"NMAKE Makefiles" -DQTSDK="C:\Qt\5.3\msvc2013" ..

4. Build

        nmake

6. Execute

        client\qdigidocclient.exe



## Support
Official builds are provided through official distribution point [installer.id.ee](https://installer.id.ee). If you want support, you need to be using official builds. Contact for assistance by email [abi@id.ee](mailto:abi@id.ee) or [www.id.ee](http://www.id.ee).

Source code is provided on "as is" terms with no warranty (see license for more information). Do not file Github issues with generic support requests.
