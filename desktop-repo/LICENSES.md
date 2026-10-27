# Сторонние компоненты

- **sing-box** (GPL-3.0-or-later): https://github.com/SagerNet/sing-box, версия 1.14.4. Исходный код доступен по этой ссылке. В архив входит неизменённый официальный бинарный файл.
- **Wintun** (только Windows, wintun.dll): https://www.wintun.net, версия 0.14.1, распространяется в виде официальных бинарных файлов по лицензии, указанной на сайте проекта.
- **uTLS** (BSD-3-Clause): https://github.com/refraction-networking/utls, используется внутри `ct`.
- **golang.org/x/crypto, golang.org/x/sys** (BSD-3-Clause).

Программа `coral` и слой `ct` запускают sing-box как отдельный процесс и не связаны с ним в один исполняемый файл.
