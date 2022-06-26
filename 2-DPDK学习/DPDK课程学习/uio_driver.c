


struct uio_info igb_uio_info = {

};



int igb_uio_probe (struct device *dev) {

}
int igb_uio_remove (struct device *dev) {

}




// pci_driver
static struct device_driver igb_uio_driver = {
	.name = "igb_uio",
	.bus = platform_bus_type,
	.probe = igb_uio_probe,
	.remove = igb_uio_remove
};


// insmod igb_uio

static struct platform_deivce *igb_uio_device;

static int __init igb_uio_init(void) {

	igb_uio_device = platform_device_register_simple("igb_uio", -1, NULL,0);

	return driver_register();

}

//
static void __exit igb_uio_exit(void) {

}


module_init(igb_uio_init);
module_exit(igb_uio_exit);




