/*
 * Copyright (c) 2019 WIOsense GmbH & Co. KG
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <ztest.h>

/**
 * External declaration of the state machine tests
 */
extern void setup_fsm(void);
extern void teardown_fsm(void);
extern void test_fsm(void);

#define NUM_TESTS          1

void test_main(void)
{
	s32_t test_duration[NUM_TESTS] = { 0 };
	s64_t time;

	ztest_test_suite(state_machine,
			 ztest_unit_test_setup_teardown(test_fsm,
							setup_fsm,
							teardown_fsm)
			);

	time = k_uptime_get_32();
	ztest_run_test_suite(state_machine);
	test_duration[0] = k_uptime_delta_32(&time);
	printk(">>>> Elapsed test time: %d ms\n\n", test_duration[0]);

	time = 0;
	for (uint8_t i = 0; i != NUM_TESTS; ++i) {
		time += test_duration[i];
	}
	printk(">>>> Tests TOTAL time: %d ms\n\n", (uint32_t)time);
}
