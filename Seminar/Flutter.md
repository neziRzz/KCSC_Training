# Flutter
## Introduction
- Được phát triển bởi Google, Flutter framework có thể giúp ta build các ứng dụng trên nhiều nền tảng khác nhau (iOS, Android,...etc) chỉ với một source code duy nhất. Source code của các app Flutter được viết bằng `Dart`
## Reversing Flutter
### Recon and Identification
- Thông thường thì dấu hiệu nhận biết một app được build bằng Flutter sẽ như sau
  + Nếu app được build bằng mode `debug` thì ta chỉ cần tìm source bên trong `./assets/flutter_assets/kernel_blob.bin`
  + Nếu app được build bằng mode `release` thì lúc này ta sẽ phải tìm `libapp.so` ở bên trong thư mục `./lib/` của APK
- **NOTE:** Bài viết này sẽ chỉ đề cập đến mode `release`
### Tools
- Để reverse được các samples được build bằng Flutter, ta có thể sử dụng một trong số tools sau
  + [Blutter](https://github.com/worawit/blutter) (Mình sẽ sử dụng tool này trong demo)
  + [Dolđrums](https://github.com/rscloura/Doldrums)
  + [reFlutter](https://github.com/Impact-I/reFlutter)
