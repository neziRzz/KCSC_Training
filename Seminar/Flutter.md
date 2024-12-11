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
  + [Doldrums](https://github.com/rscloura/Doldrums)
  + [reFlutter](https://github.com/Impact-I/reFlutter)
### Demo
- Dưới đây mình sẽ demo 1 bài [CTF](https://github.com/neziRzz/KCSC_Training/tree/main/Seminar/Demo) có sử dụng Flutter ở `release mode`, về hướng tiếp cận thì ta sẽ có 2 cách
  + Sử dụng tool `Blutter` để đọc file `main.dart`
  + Patch trực tiếp trong file `libapp.so`
#### Using Blutter
- Cách này ta sẽ sử dụng tool `Blutter` để extract các file trong `lib/arm64-v8a`. Sau khi chạy xong, ta được output là các file bên dưới

![image](https://github.com/user-attachments/assets/3e19bd67-3884-4583-88ac-40a0681240d6)

+ `asm/`: Chứa mã asm đi kèm với thông tin của các Objects cũng như là thread
+ `ida_script/`: Chứa script cho IDA giúp khôi phục lại tên các symbol bị stripped cũng như là các structs
+ `blutter_frida.js`: Giúp ta có thể hook vào các functions có trong project
+ `objs.txt`: Chứa thông tin về các objects có trong lúc khởi tạo chương trình
+ `pp.txt`: Chứa thông tin về các Darts Object

- File `main.dart` sẽ nằm bên trong `asm\truyencuoiremind3`. Bởi file này rất dài nên ta nên chỉ tìm các từ khóa liên quan đến flag như `flag`, `decrypt`, `encrypt`,etc.... Sau một hồi tìm kiếm thì ta sẽ tìm được cơ chế decrypt flag của chương trình 
```dart
_ _decryptMessage(/* No info */) {
    // ** addr: 0x2241f4, size: 0xe8
    // 0x2241f4: EnterFrame
    //     0x2241f4: stp             fp, lr, [SP, #-0x10]!
    //     0x2241f8: mov             fp, SP
    // 0x2241fc: AllocStack(0x20)
    //     0x2241fc: sub             SP, SP, #0x20
    // 0x224200: SetupParameters(_MyHomePageState this /* r1 => r2, fp-0x8 */, dynamic _ /* r2 => r0, fp-0x10 */)
    //     0x224200: mov             x0, x2
    //     0x224204: stur            x2, [fp, #-0x10]
    //     0x224208: mov             x2, x1
    //     0x22420c: stur            x1, [fp, #-8]
    // 0x224210: CheckStackOverflow
    //     0x224210: ldr             x16, [THR, #0x38]  ; THR::stack_limit
    //     0x224214: cmp             SP, x16
    //     0x224218: b.ls            #0x2242d4
    // 0x22421c: LoadField: r1 = r2->field_27
    //     0x22421c: ldur            w1, [x2, #0x27]
    // 0x224220: DecompressPointer r1
    //     0x224220: add             x1, x1, HEAP, lsl #32
    // 0x224224: r0 = StringcareStringExt.reveal()
    //     0x224224: bl              #0x24e430  ; [package:stringcare/src/extension/stringcare_ext.dart] ::StringcareStringExt.reveal
    // 0x224228: stur            x0, [fp, #-0x18]
    // 0x22422c: r0 = Key()
    //     0x22422c: bl              #0x24e424  ; AllocateKeyStub -> Key (size=0xc)
    // 0x224230: mov             x1, x0
    // 0x224234: ldur            x2, [fp, #-0x18]
    // 0x224238: stur            x0, [fp, #-0x18]
    // 0x22423c: r0 = Encrypted.fromUtf8()
    //     0x22423c: bl              #0x24e22c  ; [package:encrypt/encrypt.dart] Encrypted::Encrypted.fromUtf8
    // 0x224240: ldur            x0, [fp, #-8]
    // 0x224244: LoadField: r1 = r0->field_2b
    //     0x224244: ldur            w1, [x0, #0x2b]
    // 0x224248: DecompressPointer r1
    //     0x224248: add             x1, x1, HEAP, lsl #32
    // 0x22424c: r0 = StringcareStringExt.reveal()
    //     0x22424c: bl              #0x24e430  ; [package:stringcare/src/extension/stringcare_ext.dart] ::StringcareStringExt.reveal
    // 0x224250: stur            x0, [fp, #-8]
    // 0x224254: r0 = IV()
    //     0x224254: bl              #0x24e220  ; AllocateIVStub -> IV (size=0xc)
    // 0x224258: mov             x1, x0
    // 0x22425c: ldur            x2, [fp, #-8]
    // 0x224260: stur            x0, [fp, #-8]
    // 0x224264: r0 = Encrypted.fromUtf8()
    //     0x224264: bl              #0x24e22c  ; [package:encrypt/encrypt.dart] Encrypted::Encrypted.fromUtf8
    // 0x224268: r0 = AES()
    //     0x224268: bl              #0x24e214  ; AllocateAESStub -> AES (size=0x1c)
    // 0x22426c: mov             x1, x0
    // 0x224270: ldur            x2, [fp, #-0x18]
    // 0x224274: stur            x0, [fp, #-0x18]
    // 0x224278: r0 = AES()
    //     0x224278: bl              #0x22458c  ; [package:encrypt/encrypt.dart] AES::AES
    // 0x22427c: r0 = Encrypter()
    //     0x22427c: bl              #0x224580  ; AllocateEncrypterStub -> Encrypter (size=0xc)
    // 0x224280: mov             x2, x0
    // 0x224284: ldur            x0, [fp, #-0x18]
    // 0x224288: stur            x2, [fp, #-0x20]
    // 0x22428c: StoreField: r2->field_7 = r0
    //     0x22428c: stur            w0, [x2, #7]
    // 0x224290: ldur            x1, [fp, #-0x10]
    // 0x224294: r0 = StringcareStringExt.reveal()
    //     0x224294: bl              #0x24e430  ; [package:stringcare/src/extension/stringcare_ext.dart] ::StringcareStringExt.reveal
    // 0x224298: mov             x2, x0
    // 0x22429c: r1 = Instance_Base64Codec
    //     0x22429c: ldr             x1, [PP, #0x1438]  ; [pp+0x1438] Obj!Base64Codec@42dd11
    // 0x2242a0: r0 = decode()
    //     0x2242a0: bl              #0x22454c  ; [dart:convert] Base64Codec::decode
    // 0x2242a4: stur            x0, [fp, #-0x10]
    // 0x2242a8: r0 = Encrypted()
    //     0x2242a8: bl              #0x224540  ; AllocateEncryptedStub -> Encrypted (size=0xc)
    // 0x2242ac: mov             x1, x0
    // 0x2242b0: ldur            x0, [fp, #-0x10]
    // 0x2242b4: StoreField: r1->field_7 = r0
    //     0x2242b4: stur            w0, [x1, #7]
    // 0x2242b8: mov             x2, x1
    // 0x2242bc: ldur            x1, [fp, #-0x20]
    // 0x2242c0: ldur            x3, [fp, #-8]
    // 0x2242c4: r0 = decrypt()
    //     0x2242c4: bl              #0x2242dc  ; [package:encrypt/encrypt.dart] Encrypter::decrypt
    // 0x2242c8: LeaveFrame
    //     0x2242c8: mov             SP, fp
    //     0x2242cc: ldp             fp, lr, [SP], #0x10
    // 0x2242d0: ret
    //     0x2242d0: ret             
    // 0x2242d4: r0 = StackOverflowSharedWithoutFPURegs()
    //     0x2242d4: bl              #0x36febc  ; StackOverflowSharedWithoutFPURegsStub
    // 0x2242d8: b               #0x22421c
  }
```
