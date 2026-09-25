plugins {
    id("com.android.asset-pack")
}

assetPack {
    packName.set("install_assets")
    dynamicDelivery {
        deliveryType.set("install-time")
    }
}
