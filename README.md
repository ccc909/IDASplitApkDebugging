## This will be a short guide on how to debug native (.so) libraries from split_apks using IDA

If there are any problems or features that you think would be helpful please open as issue.

If crashing, please try disabling analysis before rebasing.

1. Ensure you have a rooted phone.
2. Download platform-tools from https://developer.android.com/tools/releases/platform-tools and preferably add them to your path.
3. Locate the IDA android_server (armv8, 64bit) / android_server32 (armv7, 32bit) packaged with IDA in the `.../IDAPRO/dbgsrv` directory.
4. Run the following command:
   ```bash
   adb push <your android server> /data/local/tmp
   ```
   Example:
   ```bash
   adb push ./android_server /data/local/tmp
   ```

Now we have the android server on the device and we start a debug session.

1. Load up the library you want to debug in IDA.
2. Press **F9** and select the Remote ARM Linux/Android debugger.
3. Navigate to **Debugger->Process Options** in IDA, make sure the hostname is `localhost` and note down your port.
4. Start the debug server on your device by running:
   ```bash
   adb shell
   su
   cd data/local/tmp
   chmod 777 ./android_server
   ./android_server
   ```
5. Now that the server is running we must forward the port in order for our machine and the phone to communicate:
   ```bash
   adb forward tcp:<your_port_from_ida> tcp:<your_port_from_ida>
   ```
6. Start the target process on the mobile device.
7. In IDA navigate to the debugger, select your target process and attach.

We are now debugging the process but you will notice any breakpoints set will be disabled upon resuming and pausing execution.

This is due to the library loaded in IDA not being mapped to the device's memory.

On an apk that loads its native code libraries normally IDA would have detected that and automatically prompt us to rebase to the base address of the library in memory.

But with split apks this process is not performed automatically as the segments are named differently in memory due to being loaded from the bundled split_apk.

In order to find the address of the module in memory we must navigate to the **'Segments'** tab in IDA, there we can locate our split_apk that contains the module.

Performing a search with the name of the split apk we obtain a number of results as seen here:

![image](https://github.com/user-attachments/assets/e687fbd0-42ae-44f7-b6cc-a2daf5690c86)

IDA cannot find the actual names of modules and just uses the name of the parent split apk, leading to manual rebasing needing to be done in order for debugging to actually work.

Manually identifying the segment we need to rebase to was time consuming, so I created a script that can be downloaded from this repository.

To install it:
1. Copy the downloaded `segment_names.py` file to the `.../IDAPRO/plugins` folder
2. Start a debugging session
3. Run the script from **Edit->Plugins->Segment renamer with Rebasing**

You will be prompted to select the split_apk file from your computer, select it and wait for processing to be done.

If any of the files from the ABI split apk match the segments will be renamed to their proper names (refresh **'Segments'** tab to view changes), and if the currently loaded file is matched, rebasing to its start address code area is offered.
