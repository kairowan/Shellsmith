plugins {
    id("com.android.asset-pack")
}

assetPack {
    packName.set("ondemand_assets")
    dynamicDelivery {
        deliveryType.set("on-demand")
    }
}

