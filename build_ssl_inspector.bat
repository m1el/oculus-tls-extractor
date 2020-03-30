pushd openssl
git checkout OpenSSL_1_0_2o
git apply < ..\ssl_inspector.patch
call ms\do_win64a.bat
nmake -f ms\nt.mak ssl_inspector
popd
