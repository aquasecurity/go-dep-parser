To recreate test files, run:
```bash
conda create --yes -n test-dep-parser python=3.8.8
cp ~/miniconda3/envs/test-dep-parser/conda-meta/*
```
Then trim down the largest files (see `<SNIP>` in current files).

This installed:
```
_libgcc_mutex      pkgs/main/linux-64::_libgcc_mutex-0.1-main
_openmp_mutex      pkgs/main/linux-64::_openmp_mutex-5.1-1_gnu
ca-certificates    pkgs/main/linux-64::ca-certificates-2022.10.11-h06a4308_0
certifi            pkgs/main/linux-64::certifi-2022.9.24-py38h06a4308_0
ld_impl_linux-64   pkgs/main/linux-64::ld_impl_linux-64-2.38-h1181459_1
libffi             pkgs/main/linux-64::libffi-3.3-he6710b0_2
libgcc-ng          pkgs/main/linux-64::libgcc-ng-11.2.0-h1234567_1
libgomp            pkgs/main/linux-64::libgomp-11.2.0-h1234567_1
libstdcxx-ng       pkgs/main/linux-64::libstdcxx-ng-11.2.0-h1234567_1
ncurses            pkgs/main/linux-64::ncurses-6.3-h5eee18b_3
openssl            pkgs/main/linux-64::openssl-1.1.1q-h7f8727e_0
pip                pkgs/main/linux-64::pip-22.2.2-py38h06a4308_0
python             pkgs/main/linux-64::python-3.8.8-hdb3f193_5
readline           pkgs/main/linux-64::readline-8.2-h5eee18b_0
setuptools         pkgs/main/linux-64::setuptools-65.5.0-py38h06a4308_0
sqlite             pkgs/main/linux-64::sqlite-3.39.3-h5082296_0
tk                 pkgs/main/linux-64::tk-8.6.12-h1ccaba5_0
wheel              pkgs/main/noarch::wheel-0.37.1-pyhd3eb1b0_0
xz                 pkgs/main/linux-64::xz-5.2.6-h5eee18b_0
zlib               pkgs/main/linux-64::zlib-1.2.13-h5eee18b_0
```
