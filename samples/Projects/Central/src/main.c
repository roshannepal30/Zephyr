#include <zephyr/types.h>
#include <stddef.h>
#include <errno.h>
#include <zephyr.h>
#include <sys/printk.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>
#include <sys/byteorder.h>

#define MAX_WAIT_TIME	K_MSEC(30);

static void start_scan(void);

static struct bt_uuid_16 uuid = BT_UUID_INIT_16(0);
static struct bt_gatt_discover_params discover_params;
static struct bt_gatt_subscribe_params subscribe_params;
static void expiry_function(struct k_timer *timer);
static void work_handler(struct k_work *work);
static void stop_work_handler(struct k_work *stop_work);
static void stop_function(struct k_timer *timer);
   
K_TIMER_DEFINE(timer,expiry_function,stop_function);

K_WORK_DEFINE(work,work_handler);

K_WORK_DEFINE(stop_work,stop_work_handler);

static struct k_mbox_msg recv_msg;
static uint32_t random;
static struct net_buf_simple *ad;

static uint32_t buffer;
static uint32_t key[20];
static bool received;
static int i;



static bool eir_found(struct bt_data *data, void *user_data)
{
	bt_addr_le_t *addr = user_data;
	int i;

	printk("[AD]: %u data_len %u\n", data->type, data->data_len);

	switch (data->type) {
	case BT_DATA_UUID16_SOME:
	case BT_DATA_UUID16_ALL:
		if (data->data_len % sizeof(uint16_t) != 0U) {
			printk("AD malformed\n");
			return true;
		}

		for (i = 0; i < data->data_len; i += sizeof(uint16_t)) {

			struct bt_uuid *uuid;
			uint16_t u16;
			int err;

			memcpy(&u16, &data->data[i], sizeof(u16));
			uuid = BT_UUID_DECLARE_16(sys_le16_to_cpu(u16));
			if (bt_uuid_cmp(uuid, BT_UUID_PER)) {
				continue;
			}

			err = bt_le_scan_stop();
			if (err) {
				printk("Stop LE scan failed (err %d)\n", err);
				continue;
			}

			return false;
		}
	}

	return true;
}

static void device_found(const bt_addr_le_t *addr, int8_t rssi, uint8_t type,
			 struct net_buf_simple *ad)
{
	char dev[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(addr, dev, sizeof(dev));
	printk("[DEVICE]: %s, AD evt type %u, AD data len %u, RSSI %i\n",
	       dev, type, ad->len, rssi);

	/* We're only interested in connectable events */
	if (type == BT_GAP_ADV_TYPE_ADV_IND ||
	    type == BT_GAP_ADV_TYPE_ADV_DIRECT_IND) {
		bt_data_parse(ad, eir_found, (void *)addr);
		received = true;
	}
}

static void start_scan(void)
{
	int err;

	
	struct bt_le_scan_param scan_param = {
		.type       = BT_LE_SCAN_TYPE_PASSIVE,
		.options    = BT_LE_SCAN_OPT_NONE,
		.interval   = BT_GAP_SCAN_FAST_INTERVAL,
		.window     = BT_GAP_SCAN_FAST_WINDOW,
	};

	err = bt_le_scan_start(&scan_param, device_found);
	if (err) {
		printk("Scanning failed to start (err %d)\n", err);
		return;
	}

	printk("Scanning successfully started\n");
}

static void expiry_function(struct k_timer *timer)
{
        printk("Running expiry function\n");
	    k_work_submit(&work);
}
static void stop_function(struct k_timer *timer)
{
    printk("Running stop function\n");
	k_work_submit(&stop_work);
}    

	
static void work_handler(struct k_work *work)
{
    printk("Running work handler\n");
	 //();/*do the processing that needs to be done periodically, send the random bit if random wait time is elapsed,	start the session again*/
     //key[i] = random;
}

static void stop_work_handler(struct k_work *stop_work)
{
    printk("Running stop work handler\n");
    key[i] = ad;
}


void main(void)
{
	int err;
	err = bt_enable(NULL);

	if (err) {
		printk("Bluetooth init failed (err %d)\n", err);
		return;
	}

	printk("Bluetooth initialized\n");

	printk("starting the loop\n");

    for (i=0;i<20;i++){
        // transmit timer start 
        k_timer_start(&timer, K_MSEC(15), K_MSEC(30));

        //scanning for bits 
        printk("Scanning for the bits\n");
        start_scan();

        if((received=true)){
            printk("Received\n");
            k_timer_stop(&timer);
            
        }
        printk("%d\n", key[i]);
    }

    printk("Printing what is received\n");
    for (int j = 0; j<20; j++)
    {
        printk("%d", key[j]);
    }
	start_scan();
}
