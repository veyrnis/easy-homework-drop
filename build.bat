@echo off
chcp 65001 >nul
echo ========================================
echo   作业收集系统 —— 一键打包
echo ========================================
echo.

:: 检查 Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未检测到 Python，请先安装 Python 3.8+
    pause
    exit /b 1
)

:: 安装依赖
echo [1/4] 安装依赖...
pip install -q flask werkzeug pyinstaller
if errorlevel 1 (
    echo [错误] 依赖安装失败
    pause
    exit /b 1
)

:: 打包
echo [2/4] 打包 exe...
pyinstaller --onefile --name 作业收集 --clean ^
    --distpath dist --workpath build --specpath build ^
    main.py
if errorlevel 1 (
    echo [错误] 打包失败
    pause
    exit /b 1
)

:: 组装发布包
echo [3/4] 组装发布包...
if exist 发布包 rmdir /s /q 发布包
mkdir 发布包
copy dist\作业收集.exe 发布包\ >nul
copy main.py 发布包\ >nul
copy 使用说明.txt 发布包\ >nul
copy README.md 发布包\ >nul
mkdir 发布包\uploads

:: 生成哈希清单
echo [4/4] 生成 SHA256 校验值...
powershell -Command ^
  "$files = @('作业收集.exe','main.py'); ^
   $out = foreach ($f in $files) { ^
     $h = (Get-FileHash -Path ('发布包\' + $f) -Algorithm SHA256).Hash; ^
     '{0}  {1}' -f $h, $f ^
   }; ^
   $out | Out-File -Encoding utf8 发布包\SHA256.txt"

echo.
echo ========================================
echo   打包完成！
echo ========================================
echo   发布包位置：发布包\
echo   内容：
echo     - 作业收集.exe     主程序
echo     - main.py          完整源码
echo     - 使用说明.txt     说明书
echo     - README.md        项目说明
echo     - SHA256.txt       校验值
echo     - uploads\         作业存放目录
echo.
echo   把「发布包」文件夹压缩成 zip 发出去即可。
echo ========================================
pause