#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include "libklvanc/vanc.h"
//#include "core-private.h"

#define PORT 5167

#define _d(fmt, args...)     \
	{                        \
		printf(fmt, ##args); \
	}

//#define _d(...) log_cb(NULL, LIBKLVANC_LOGLEVEL_DEBUG, __VA_ARGS__);
//#define _d(m) log_cb(NULL, LIBKLVANC_LOGLEVEL_DEBUG, " %s = 0x%x\n", #m, m);

static void hexdump(unsigned char *buf, unsigned int len, int bytesPerRow)
{
	for (unsigned int i = 0; i < len; i++)
	{
		_d("%02x%s", buf[i], ((i + 1) % bytesPerRow) ? " " : "\n");
	}
	_d("\n");
}

static const char *mom_operationName(unsigned short opID)
{
	if ((opID >= 0xc000) && (opID <= 0xFFFE))
		return "User Defined";

	switch (opID)
	{
	case 0x0100:
		return "inject_section_data_request";
	case 0x0101:
		return "splice_request_data";
	case 0x0102:
		return "splice_null_request_data";
	case 0x0103:
		return "start_schedule_download_request_data";
	case 0x0104:
		return "time_signal_request_data";
	case 0x0105:
		return "transmit_schedule_request_data";
	case 0x0106:
		return "component_mode_DPI_request_data";
	case 0x0107:
		return "encrypted_DPI_request_data";
	case 0x0108:
		return "insert_descriptor_request_data";
	case 0x0109:
		return "insert_DTMF_descriptor_request_data";
	case 0x010a:
		return "insert_avail_descriptor_request_data";
	case 0x010b:
		return "insert_segmentation_descriptor_request_data";
	case 0x010c:
		return "proprietary_command_request_data";
	case 0x010d:
		return "schedule_component_mode_request_data";
	case 0x010e:
		return "schedule_definition_data_request";
	case 0x010f:
		return "insert_tier_data";
	case 0x0110:
		return "insert_time_descriptor";
	case 0x0300:
		return "delete_controlword_data_request";
	case 0x0301:
		return "update_controlword_data_request";
	default:
		return "Reserved";
	}
}

static const char *spliceInsertTypeName(unsigned char type)
{
	switch (type)
	{
	case 0x0000:
		return "reserved";
	case SPLICESTART_NORMAL:
		return "spliceStart_normal";
	case SPLICESTART_IMMEDIATE:
		return "spliceStart_immediate";
	case SPLICEEND_NORMAL:
		return "spliceEnd_normal";
	case SPLICEEND_IMMEDIATE:
		return "spliceEnd_immediate";
	case SPLICE_CANCEL:
		return "splice_cancel";
	default:
		return "Undefined";
	}
}

static const char *seg_upid_type(unsigned char upid_type)
{
	/* Values come from SCTE 35 2016, Sec 10.3.3.1, Table 21 */
	switch (upid_type)
	{
	case 0x00:
		return "Not Used";
	case 0x01:
		return "User Defined (Deprecated)";
	case 0x02:
		return "ISCI (Deprecated)";
	case 0x03:
		return "Ad-ID";
	case 0x04:
		return "UMID";
	case 0x05:
		return "ISAN (Deprecated)";
	case 0x06:
		return "ISAN";
	case 0x07:
		return "TID";
	case 0x08:
		return "TI";
	case 0x09:
		return "ADI";
	case 0x0a:
		return "EIDR";
	case 0x0b:
		return "ATSC Content Identifier";
	case 0x0c:
		return "MPU()";
	case 0x0d:
		return "MID()";
	case 0x0e:
		return "ADS Information";
	case 0x0f:
		return "URI";
	default:
		return "Reserved";
	}
}

static const char *seg_type_id(unsigned char type_id)
{
	/* Values come from SCTE 35 2019, Sec 10.3.3.1 (Table 22) */
	switch (type_id)
	{
	case 0x00:
		return "Not Indicated";
	case 0x01:
		return "Content Identification";
	case 0x10:
		return "Program Start";
	case 0x11:
		return "Program End";
	case 0x12:
		return "Program Early Termination";
	case 0x13:
		return "Program Breakaway";
	case 0x14:
		return "Program Resumption";
	case 0x15:
		return "Program Runover Planned";
	case 0x16:
		return "Program Runover Unplanned";
	case 0x17:
		return "Program Overlap Start";
	case 0x18:
		return "Program Blackout Override";
	case 0x19:
		return "Program Start - In Progress";
	case 0x20:
		return "Chapter Start";
	case 0x21:
		return "Chapter End";
	case 0x22:
		return "Break Start";
	case 0x23:
		return "Break End";
	case 0x24:
		return "Opening Credit Start";
	case 0x25:
		return "Opening Credit End";
	case 0x26:
		return "Closing Credit Start";
	case 0x27:
		return "Closing Credit End";
	case 0x30:
		return "Provider Advertisement Start";
	case 0x31:
		return "Provider Advertisement End";
	case 0x32:
		return "Distributor Advertisement Start";
	case 0x33:
		return "Distributor Advertisement End";
	case 0x34:
		return "Provider Placement Opportunity Start";
	case 0x35:
		return "Provider Placement Opportunity End";
	case 0x36:
		return "Distributor Placement Opportunity Start";
	case 0x37:
		return "Distributor Placement Opportunity End";
	case 0x38:
		return "Provider Overlay Placement Start";
	case 0x39:
		return "Provider Overlay Placement End";
	case 0x3A:
		return "Distributor Overlay Placement Start";
	case 0x3B:
		return "Distributor Overlay Placement End";
	case 0x40:
		return "Unscheduled Event Start";
	case 0x41:
		return "Unscheduled Event End";
	case 0x50:
		return "Network Start";
	case 0x51:
		return "Network End";
	default:
		return "Unknown";
	}
}

static const char *seg_device_restrictions(unsigned char val)
{
	/* Values come from SCTE 35 2016, Sec 10.3.3.1, Table 21 */
	switch (val)
	{
	case 0x00:
		return "Restrict Group 0";
	case 0x01:
		return "Restrict Group 1";
	case 0x02:
		return "Restrict Group 2";
	case 0x03:
		return "None";
	default:
		return "Unknown";
	}
}

static unsigned char *parse_mom_timestamp(unsigned char *p, struct klvanc_multiple_operation_message_timestamp *ts)
{
	ts->time_type = *(p++);
	switch (ts->time_type)
	{
	case 1:
		ts->time_type_1.UTC_seconds = *(p + 0) << 24 | *(p + 1) << 16 | *(p + 2) << 8 | *(p + 3);
		ts->time_type_1.UTC_microseconds = *(p + 4) << 8 | *(p + 5);
		p += 6;
		break;
	case 2:
		ts->time_type_2.hours = *(p + 0);
		ts->time_type_2.minutes = *(p + 1);
		ts->time_type_2.seconds = *(p + 2);
		ts->time_type_2.frames = *(p + 3);
		p += 4;
		break;
	case 3:
		ts->time_type_3.GPI_number = *(p + 0);
		ts->time_type_3.GPI_edge = *(p + 1);
		p += 2;
		break;
	case 0:
		/* The spec says no time is defined, this is a legitimate state. */
		break;
	default:
		_d("%s() unsupported time_type 0x%x, assuming no time.\n", __func__, ts->time_type);
	}

	return p;
}

static unsigned char *parse_splice_request_data(unsigned char *p, struct klvanc_splice_request_data *d)
{
	d->splice_insert_type = *(p++);
	d->splice_event_id = *(p + 0) << 24 | *(p + 1) << 16 | *(p + 2) << 8 | *(p + 3);
	p += 4;
	d->unique_program_id = *(p + 0) << 8 | *(p + 1);
	p += 2;
	d->pre_roll_time = *(p + 0) << 8 | *(p + 1);
	p += 2;
	d->brk_duration = *(p + 0) << 8 | *(p + 1);
	p += 2;
	d->avail_num = *(p++);
	d->avails_expected = *(p++);
	d->auto_return_flag = *(p++);

	/* TODO: We don't support splice cancel, but we'll pass it through with a warning. */
	switch (d->splice_insert_type)
	{
	case SPLICESTART_IMMEDIATE:
	case SPLICEEND_IMMEDIATE:
	case SPLICESTART_NORMAL:
	case SPLICEEND_NORMAL:
	case SPLICE_CANCEL:
		break;
	default:
		/* We don't support this splice command */
		_d("%s() splice_insert_type 0x%x [%s], error.\n", __func__, d->splice_insert_type, spliceInsertTypeName(d->splice_insert_type));
	}

	return p;
}

static int parse_multiple_operation_message(unsigned char *payload, struct klvanc_multiple_operation_message *mom)
{
	mom->rsvd = payload[0] << 8 | payload[1];
	mom->messageSize = payload[2] << 8 | payload[3];
	mom->protocol_version = payload[4];
	mom->AS_index = payload[5];
	mom->message_number = payload[6];
	mom->DPI_PID_index = payload[7] << 8 | payload[8];
	mom->SCTE35_protocol_version = payload[9];

	unsigned char *p = &payload[10];
	p = parse_mom_timestamp(p, &mom->timestamp);

	mom->num_ops = *(p++);
	mom->ops = (klvanc_multiple_operation_message_operation *)calloc(mom->num_ops, sizeof(struct klvanc_multiple_operation_message_operation));
	if (!mom->ops)
	{
		_d("%s() unable to allocate momo ram, error.\n", __func__);
	}

	for (int i = 0; i < mom->num_ops; i++)
	{
		struct klvanc_multiple_operation_message_operation *o = &mom->ops[i];
		o->opID = *(p + 0) << 8 | *(p + 1);
		o->data_length = *(p + 2) << 8 | *(p + 3);
		o->data = (unsigned char *)malloc(o->data_length);
		if (!o->data)
		{
			_d("%s() Unable to allocate memory for mom op, error.\n", __func__);
		}
		else
		{
			memcpy(o->data, p + 4, o->data_length);
		}
		p += (4 + o->data_length);

		if (o->opID == MO_SPLICE_REQUEST_DATA)
		{
			parse_splice_request_data(o->data, &o->sr_data);
			//_d("opID = 0x%04x [%s], length = 0x%04x \n", o->opID, mom_operationName(o->opID), o->data_length);
			_d("opID = 0x%04x [%s], length = %d \n", o->opID, mom_operationName(o->opID), o->data_length);
		}
		else
		{
			//_d("opID = 0x%04x [%s], length = 0x%04x \n", o->opID, mom_operationName(o->opID), o->data_length);
			_d("opID = 0x%04x [%s], length = %d \n", o->opID, mom_operationName(o->opID), o->data_length);
		}
	}

	/* We'll parse this message but we'll only look for INIT_REQUEST_DATA
		 * sub messages, and construct a splice_request_data message.
		 * The rest of the message types will be ignored.
		 */
	return 0;
}

static int print_multi_message(struct klvanc_multiple_operation_message *m)
{
	_d("SCTE104 multiple_operation_message struct\n");

	_d("    rsvd = %s\n", m->rsvd == 0xFFFF ? "Multiple_Ops (Reserved)" : "UNSUPPORTED");
	_d("message size : 0x%x\n", m->messageSize);
	_d("protocol version : 0x%x\n", m->protocol_version);
	_d("AS_index : 0x%x\n", m->AS_index);
	_d("message number : 0x%x\n", m->message_number);
	_d("DPI_PID_index : 0x%x\n", m->DPI_PID_index);
	_d("SCTE35_protocol_version : 0x%x\n", m->SCTE35_protocol_version);
	//_d_debug_member_timestamp(ctx, &m->timestamp);
	_d("num ops : %d\n", m->num_ops);

	for (int i = 0; i < m->num_ops; i++)
	{
		struct klvanc_multiple_operation_message_operation *o = &m->ops[i];
		_d("\n opID[%d] = %s\n", i, mom_operationName(o->opID));
		_d("data length : %d\n", o->data_length);
		if (o->data_length)
			hexdump(o->data, o->data_length, 16);
		if (o->opID == MO_SPLICE_REQUEST_DATA)
		{
			struct klvanc_splice_request_data *d = &o->sr_data;
			_d("splice_insert_type = %s\n", spliceInsertTypeName(d->splice_insert_type));
			_d("splice event id : 0x%x\n", d->splice_event_id);
			_d("unique program id : 0x%x\n", d->unique_program_id);
			_d("pre_roll_time = %d (milliseconds)\n", d->pre_roll_time);
			_d("break_duration = %d (1/10th seconds)\n", d->brk_duration);
			_d("avail_num : %d\n", d->avail_num);
			_d("avails_expected : %d\n", d->avails_expected);
			_d("auto return flag : %d\n", d->auto_return_flag);
		}

		/*
		else if (o->opID == MO_TIME_SIGNAL_REQUEST_DATA)
		{
			struct klvanc_time_signal_request_data *d = &o->timesignal_data;
			_d("    pre_roll_time = %d (milliseconds)\n", d->pre_roll_time);
		}
		else if (o->opID == MO_INSERT_DESCRIPTOR_REQUEST_DATA)
		{
			struct klvanc_insert_descriptor_request_data *d = &o->descriptor_data;
			_d(d->descriptor_count);
			_d(d->total_length);
			for (int j = 0; j < d->total_length; j++)
			{
				_d(d->descriptor_bytes[j]);
			}
		}
		else if (o->opID == MO_INSERT_AVAIL_DESCRIPTOR_REQUEST_DATA)
		{
			struct klvanc_avail_descriptor_request_data *d = &o->avail_descriptor_data;
			_d(d->num_provider_avails);
			for (int j = 0; j < d->num_provider_avails; j++)
			{
				_d(d->provider_avail_id[j]);
			}
		}
		else if (o->opID == MO_INSERT_DTMF_REQUEST_DATA)
		{
			struct klvanc_dtmf_descriptor_request_data *d = &o->dtmf_data;
			_d(d->pre_roll_time);
			_d(d->dtmf_length);
			for (int j = 0; j < d->dtmf_length; j++)
			{
				_d(d->dtmf_char[j]);
			}
		}
		else if (o->opID == MO_INSERT_SEGMENTATION_REQUEST_DATA)
		{
			struct klvanc_segmentation_descriptor_request_data *d = &o->segmentation_data;
			_d(d->event_id);
			_d(d->event_cancel_indicator);
			_d(d->duration);
			_d("    duration = %d (seconds)\n", d->duration);
			_d(d->upid_type);
			_d(" d->upid_type = 0x%02x (%s)\n", d->upid_type, seg_upid_type(d->upid_type));
			_d(d->upid_length);
			for (int j = 0; j < d->upid_length; j++)
			{
				_d(d->upid[j]);
			}
			_d(" d->type_id = 0x%02x (%s)\n", d->type_id, seg_type_id(d->type_id));
			_d(d->segment_num);
			_d(d->segments_expected);
			_d(d->duration_extension_frames);
			_d(d->delivery_not_restricted_flag);
			_d(d->web_delivery_allowed_flag);
			_d(d->no_regional_blackout_flag);
			_d(d->archive_allowed_flag);
			_d(" d->device_restrictions = 0x%02x (%s)\n", d->device_restrictions, seg_device_restrictions(d->device_restrictions));
		}
		else if (o->opID == MO_INSERT_TIER_DATA)
		{
			struct klvanc_tier_data *d = &o->tier_data;
			_d(d->tier_data);
		}
		else if (o->opID == MO_INSERT_TIME_DESCRIPTOR)
		{
			struct klvanc_time_descriptor_data *d = &o->time_data;
			_d(d->TAI_seconds);
			_d(d->TAI_ns);
			_d(d->UTC_offset);
		}
		*/
	}

	return 0;
}

int main(void)
{
	int sock, client_sock;
	struct sockaddr_in addr, client_addr;
	unsigned char buffer[1024];
	int len, addr_len, recv_len;
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("socket ");
		return 1;
	}
	memset(&addr, 0x00, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(PORT);
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		perror("bind ");
		return 1;
	}
	if (listen(sock, 5) < 0)
	{
		perror("listen ");
		return 1;
	}
	addr_len = sizeof(client_addr);
	_d("waiting for clinet..\n");

	struct klvanc_multiple_operation_message mo_msg;

	while ((client_sock = accept(sock, (struct sockaddr *)&client_addr, (socklen_t *)&addr_len)) > 0)
	{
		_d("clinet ip : %s\n", inet_ntoa(client_addr.sin_addr));
		if ((recv_len = recv(client_sock, buffer, 1024, 0)) < 0)
		{
			perror("recv ");
			return 1;
			break;
		}
		//buffer[recv_len] = '\0';
		//_df("received data : %02x\n", buffer);
		for (int i = 0; i < recv_len; i++)
		{
			_d("%02x ", buffer[i]);
		}

		_d("\n");

		parse_multiple_operation_message(buffer, &mo_msg);

		print_multi_message(&mo_msg);

		/*
		char sendbuf[16] = "Hello";
		sendbuf[sizeof(sendbuf - 1)] = '\0';
		send(client_sock, sendbuf, strlen(sendbuf), 0);
		*/
		close(client_sock);
	}
	close(sock);
	return 0;
}