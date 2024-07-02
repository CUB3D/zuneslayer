# Tools for Zune update files

### Extract a cab
```shell
cd tools && cargo r --release -- --input <path/to/DracoBaseline.cab> --out ext/ decompress-cab
```