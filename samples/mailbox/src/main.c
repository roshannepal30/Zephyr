#include <zephyr.h>
#include <drivers/entropy.h>
#include <stdio.h>
#include <kernel.h>
#include <stdlib.h>
#include <time.h>


#define MAX_WAIT_TIME	K_MSEC(30)
#define TRUE 1
#define FALSE 0
  
K_MBOX_DEFINE(mailbox);
static void expiry_function(struct k_timer *timer);
static void work_handler(struct k_work *work);
static void stop_work_handler(struct k_work *stop_work);
static void stop_function(struct k_timer *timer);
   
K_TIMER_DEFINE(timer,expiry_function,stop_function);

K_WORK_DEFINE(work,work_handler);

K_WORK_DEFINE(stop_work,stop_work_handler);

static struct k_mbox_msg recv_msg;
static uint32_t random;

static uint32_t buffer;
static uint32_t key[20];
static bool received;
static int i;

void producer_thread(void)
{
    printk("Running producer thread\n");
    struct k_mbox_msg send_msg;
        /*generate random value to send*/
        //srand(time(NULL));
        random=rand()%2;
        uint32_t buffer_msg=random;
        printk("The random number generated is %d\n", random);
    


        /* prepare to send message */

        send_msg.info=10;
        send_msg.size=1;
        send_msg.tx_data = &buffer_msg;
        send_msg.tx_block.data=0;
        send_msg.tx_target_thread= K_ANY;
        /* send message and wait until a consumer receives it */

        k_mbox_put(&mailbox, &send_msg, K_MSEC(30));
        
}

void consumer_thread(void)
{
        printk("Running consumer thread\n");
        /* prepare to receive message */
        //recv_msg.info;
        recv_msg.size=1;
        recv_msg.rx_source_thread = K_ANY;

        /* get a data item, waiting as long as needed */
        k_mbox_get(&mailbox, &recv_msg, &buffer, K_MSEC(30));

        /* info, size, and rx_source_thread fields have been updated */

         if(recv_msg.info==10){
            received=TRUE;
        }
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
	 producer_thread();/*do the processing that needs to be done periodically, send the random bit if random wait time is elapsed,	start the session again*/
     key[i] = random;
}

static void stop_work_handler(struct k_work *stop_work)
{
    printk("Running stop work handler\n");
    key[i] = buffer;
}


void main(void)
{
    printk("starting the loop\n");
    for (i=0;i<20;i++){
        // transmit timer start 
        k_timer_start(&timer, K_MSEC(15), K_MSEC(30));

        //scanning for bits 
        printk("Scanning for the bits\n");
        consumer_thread();

        if((received=TRUE)){
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

}
