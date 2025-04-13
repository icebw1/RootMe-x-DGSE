Java.perform(function() {
    var HomeViewModel = Java.use('com.nullvastation.cryssage.ui.home.HomeViewModel');
    var Build = Java.use('android.os.Build');
    
    var successfulDecryptions = {};
    var validDevices = [];
    var testedCombos = new Set();
    var FLAG_PATTERN = "RM{";

    function isValidText(text) {
        if (!text) return false;
        if (text.indexOf(FLAG_PATTERN) !== -1) return true;
        var readable = 0;
        for (var i = 0; i < text.length; i++) {
            var c = text.charCodeAt(i);
            // Readable characters are between 32 (space) and 126 (tilde ~)
            if ((c >= 32 && c <= 126) || c === 9 || c === 10 || c === 13) readable++;
        }
        // The text is valid if more than 70% of the characters are legible and it has a length > 5
        return (readable / text.length > 0.7) && (text.length > 5);
    }

    var deviceList = [];

    rpc.exports = {
        loaddevices: function(devices) {
            deviceList = devices;
            console.log("[*] Loaded " + devices.length + " devices from CSV");
    
            // Display the first device, to see if the data in the csv file is loaded correctly
            if (devices.length > 0) {
                console.log("First device loaded: " + JSON.stringify(devices[0]));
            }
        }
    };

    HomeViewModel.decryptMessage.implementation = function(encryptedMessage) {
        if (deviceList.length === 0) {
            console.log("⚠️ Device list is empty — skipping decryption.");
            return "[Error] Device list not loaded yet";
        }
        
        console.log("decryptMessage called with: " + encryptedMessage);

        if (successfulDecryptions[encryptedMessage]) {
            var cached = successfulDecryptions[encryptedMessage];
            Build.MODEL.value = cached.model;
            Build.BRAND.value = cached.brand;
            var result = this.decryptMessage.call(this, encryptedMessage);
            console.log("Using cached credentials: " + cached.model + "/" + cached.brand);
            return result;
        }

        var originalModel = Build.MODEL.value;
        var originalBrand = Build.BRAND.value;
        var result = null;
        var found = false;

        console.log("[*] Starting decryption attempts...");

        for (var i = 0; i < deviceList.length && !found; i++) {
            var model = deviceList[i].model;
            var brand = deviceList[i].brand;
            var comboKey = model + "|" + brand;

            if (testedCombos.has(comboKey)) continue;  // Skip already tested combos
            testedCombos.add(comboKey);

            try {
                Build.MODEL.value = model;
                Build.BRAND.value = brand;

                result = this.decryptMessage.call(this, encryptedMessage);

                // Check if decryption was successful and the result is valid
                if (result === null || result === undefined) {
                    console.log("Decryption returned null or undefined for combo: " + comboKey);
                    continue;
                }

                // If the result is valid, log success
                if (result !== "[Encrypted] This message was encrypted with old device credentials" && isValidText(result)) {
                    console.log("✅ Success, message: " + result);

                    successfulDecryptions[encryptedMessage] = { model: model, brand: brand };
                    validDevices.push({ model: model, brand: brand });

                    if (result.indexOf(FLAG_PATTERN) !== -1) {
                        console.log("🚩 FLAG FOUND: " + result);
                    }
                    else {
                        console.log("Decrypted message: " + result);
                    }
                    
                    found = true;
                    break;
                }

            } catch (e) {
                console.log("Error decrypting message for combo: " + comboKey);
                console.log("Error: " + e);
            }
        }

        if (!found) {
            Build.MODEL.value = originalModel;
            Build.BRAND.value = originalBrand;
            result = "[Fail] No key found to decrypt this message.";
        }

        return result;
    };

});
