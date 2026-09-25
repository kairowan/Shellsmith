plugins {
    id("com.android.asset-pack")
}

assetPack {
    packName.set("fast_assets")
    dynamicDelivery {
        deliveryType.set("fast-follow")
    }
}

