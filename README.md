# Sample plugins for PLCTool - A PRIME/DLMS graphical swiss-knife

This repostory contains the source code of the sample **Blink Attack Plugin** for **PLCTool**, a Qt-based graphical tool used to analyze and debug PRIME / DLMS-based smart-meter networks, with special focus on the security of these deployments.

Currently, **we support GNU/Linux and probably other Unix-based environments.** Windows support is on its way.

This tool was presented in the talk **Hacking Smart Meters** of the RootedCON 2022, during which its use with the **ATPL360-EK** evaluation kit to send and receive data in PLC networks was demonstrated.

## Build

Plugin build and usage guide here: [**PLCTool plugin support**](https://www.tarlogic.com/blog/plctool-plugin-support/)

Note that in order to build PLCTool and its plugins, you will need:
- A suitable C++ compiler (gcc 10.3 or higher)
- Qt 5 development files, version 5.9.1 or higher

And don't forget to install PLCTool prior to building any plugin.
