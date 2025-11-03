/* TCP_FlexiR -- a receiver side LBE congestion control algorithm
 * 
 * Copyright 2025 Qian Li
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */	

#include <linux/module.h>
#include <net/tcp.h>
#include <net/tcp_states.h>
#include <linux/list.h>
#include <linux/time64.h>

/*
 * Except xi, all parameters are design parameters. 
 * An end user is not supposed to change the default values of design parameters.
 */

/********* congestion detection parameters *********/
// threshold for high queuing delay, in ms
static int delta __read_mostly = 5;
module_param(delta, int, 0644);
// threshold for freezing rwnd, in ms
static int theta __read_mostly = 30;
module_param(theta, int, 0644);
// threshold for decreasing rwnd, in ms
static int tau __read_mostly = 100;
module_param(tau, int, 0644);

/********* rwnd decrease parameters *********/
// in percentage
static int gamma __read_mostly = 83;
module_param(gamma, int, 0644);
// used to determine how rwnd should be reduced
static int zeta __read_mostly = 92;
module_param(zeta, int, 0644);

/********* rwnd increase parameters *********/
static int lamda __read_mostly = 30;
module_param(lamda, int, 0644);
static int beta __read_mostly = 40;
module_param(beta, int, 0644);
static int alpha __read_mostly = 100;
module_param(alpha, int, 0644);

/********* window update ack parameters *********/
// whether flexir is allowed to send extra window update acks
static int xi __read_mostly = 1;
module_param(xi, int, 0644);
// the window update ack timer interval, in ms
static int phi __read_mostly = 15;
module_param(phi, int, 0644);
// error toleration, in ms 
static int mu __read_mostly = 10;
module_param(mu, int, 0644);

/********* rwnd validation parameters *********/
// threshold for invalid rwnd, in MSS
static int epsilon __read_mostly = 4;
module_param(epsilon, int, 0644);
// threshold for valid rwnd, in percentage
static int eta __read_mostly = 80;
module_param(eta, int, 0644);

/********* generic parameters *********/
// minimum rwnd, in MSS
static int iota __read_mostly = 2;
module_param(iota, int, 0644);

/********* Macros **********/
#define MAX_U32 0xffffffff
#define MAX_RTT MAX_U32
#define INF_WND MAX_U32
#define TSS 1448
#define MPRS_SEGS 4U

/*
 * @INIT: inital state
 * @INC: rwnd is being increased
 * @DEC: rwnd is being decreased
 */
enum flexir_states {
	INIT,        
	INC,         
	DEC
};
/*
 * @INORD: a segment arrived in order
 * @OUTORD: a segment arrived out of order 
 * @RETRANS: a retransmited segment 
 * @DUP: a duplicate segment 
 */
enum seg_class {
	INORD,    
	OUTORD,     
	RETRANS,   
	DUP        
};
/*
 * @TBD: to be determined
 * @INIT_DEC: rwnd reduction at the beginning of a connection 
 * @DELAY_DEC: rwnd reduction due to long queuing delay 
 * @LOSS_DEC: rwnd reduction due to segment loss
 * @VLD_DEC: rwnd reduction due to invalid rwnd 
 * @IDL_DEC: rwnd reduction due to idle
 * @MPRS_DEC: rwnd reduction due to memory pressure
 */
enum dec_reasons {
	TBD,         
	INIT_DEC,    
	DELAY_DEC,   
	LOSS_DEC,    
	VLD_DEC,    
	IDL_DEC,     
	MPRS_DEC     
};
/*
 * reasons for freezing rwnd 
 * @CNG: FlexiR is in congestion alert
 * @OFO: segments are arriving out of order
 * @SLM: rate is being limited by the sender
 * @NOROOM: no room or rcv_ssthresh has been increased to its maximum
 * @MEMPRS: the system is under memory pressure
 */
enum freeze_reasons {
	CNG,
	OFO,
	SLM,
	NOROOM,
	MEMPRS
};
/*
 * flags for freezing rwnd
 */
enum freeze_flags {
	F_CNG = (1U << CNG),
	F_OFO = (1U << OFO),
	F_SLM = (1U << SLM),
	F_NOROOM = (1U << NOROOM),
	F_MEMPRS = (1U << MEMPRS)
};

/*
 * storing the start time and reasons for freezing rwnd 
 * @start_ms: the time when rwnd freeze mode is entered, in ms
 * @reasons: the reasons why rwnd should be frozen
 */
struct freeze {
	u64 start_ms;
	u8 reasons;
};
/*
 * storing timestamps of segments having the same tsecr 
 */
struct timestamps {
	u32 tsecr;
	u32 tsval;
};
/*
 * storing ack related information
 * @snt_time_ms: when the ack was sent, in ms
 * @tsval: the tsval of the ack 
 * @adv_wnd: the window advertised by the ack
 * @rcv_nxt_high: the highest seqno received plus 1 (permitting holes) at the time when the ack was sent
 */
struct ack {
	struct list_head links;
	u64 snt_time_ms;
	u32 tsval;
	u32 adv_wnd;
	u32 rcv_nxt_high;
};
/*
 * a queue of acks sent in last RTT
 * @act_wnd: an estimate of the actual window
 * @lic: large ack inter-departure interval counter
 */
struct ack_que {
	struct list_head head;
	u32 act_wnd;
	u32 lic;
};
/*
 * @t_last_seg: the arrival time of the last segment
 * @t_last_inc: the most recent time when rcv_ssthresh was increased
 * @t_cong_alert: the time when FlexiR enters congestion alert
 * @t_invalid_rwnd: the time when the connection becomes non-rwnd limited
 * @t0: the time when the current increase mode is entered
 * @exp_term: the exponential term of the increase function: lamda * TSS * (1 + beta / 100) ^ (x / alpha)
 * @const_term: the constant term of the increase function: r0 - lamda * TSS
 * @memprs_ssthresh: the maximum value for rcv_ssthresh during memory pressure
 * @rtt_ms: the latest rtt measurement, in ms
 * @base_rtt: the observed minimum rtt of a connection
 * @srtt_ms: smoothed (with EWMA) rtt
 * @rttdev_ms: rtt deviation
 * @rttdev_life_max: the life time maximum of rtt deviation
 * @rttdev_round_max: the maximum rtt deviation in one rtt
 * @round_start: the start of an rtt
 * @act_wnd: the estimated actual window
 * @adv_wnd: the advertised window by an ack
 * @last_rwnd: the window advertised by last ack
 * @tsval_dec_done: the tsval of an ack which was sent when rcv_wnd is firstly reduced to rcv_ssthresh
 * @edge_seq: rcv_nxt_high at the time when decrease mode is quit, used to prevent duplicate rwnd reduction
 * @state: the state of FlexiR
 * @dec_reason: the reason for rwnd reduction
 * @seen_fst_ack: if the first ack has been sent
 */ 
struct vars {
	struct ack_que ack_que;
	struct freeze freeze;
	struct timestamps seg_ts;
	u64 t_last_seg;
	u64 t_last_inc;
	u64 t_cong_alert;
	u64 t_invalid_rwnd;
	u64 t0; 
	u64 exp_term;
	s64 const_term;
	u32 memprs_ssthresh;
	s32 rtt_ms;
	u32 base_rtt;
	u32 srtt_ms;
	u32 rttdev_ms;
	u32 rttdev_life_max;
	u32 rttdev_round_max;
	u32 round_start;
	u32 act_wnd;
	u32 adv_wnd;
	u32 last_rwnd;
	u32 tsval_dec_done;
	u32 rcv_nxt_high;
	u32 edge_seq;
	u8  state: 2,
	    dec_reason: 3,
		seen_fst_ack: 1,
	    unused: 2;
};
/*
 * FlexiR's private data
 * @wnd_upd_timer: window update ack timer
 */
struct flexir {
	struct hrtimer wnd_upd_timer;
	struct vars *vars;
};

/*************************************************************
 ********************* FlexiR's internal functions ********************
 ************************************************************/
/*
 * given a pointer to a socket, returning a pointer to Flexir's private data struct
 */
static void *get_priv(const struct sock *sk)
{
	return (void *)tcp_sk(sk)->rcv_cc.priv;
}

/*
 * given a pointer to a timer, returning a pointer to the containing socket
 */
static struct sock *hrtimer_to_sk(struct hrtimer *t, const char *name)
{
	struct flexir *flexir;
	struct tcp_rcv_cc *rcc;
	struct tcp_sock *tp;

	if (strcmp(name, "wnd_upd_timer") == 0)
		flexir = container_of(t, struct flexir, wnd_upd_timer);
	else
		return NULL;
	rcc = container_of((void*)flexir, struct tcp_rcv_cc, priv);
	tp = container_of(rcc, struct tcp_sock, rcv_cc);

	return (struct sock *)tp;
}

/*
 * adding the lastest ack into ack_que. acks with the same tsval are merged into one entry. 
 */
static void ack_enqueue(struct ack_que *ack_que, u64 snt_time_ms, u32 tsval, u32 adv_wnd, u32 rcv_nxt_high)
{
	struct ack *new, *last;
	long itv = 0;

	if (!list_empty(&ack_que->head)) {
		last = list_last_entry(&ack_que->head, struct ack, links);
		if (last->tsval == tsval) {
			last->adv_wnd = adv_wnd;
			last->rcv_nxt_high = rcv_nxt_high;
			return;
		} else {
			itv = snt_time_ms - last->snt_time_ms;
		}
	}
	new = kzalloc(sizeof(struct ack), GFP_KERNEL);
	if (!new) {
		return;
	}
	new->snt_time_ms = snt_time_ms;
	new->tsval = tsval;
	new->adv_wnd = adv_wnd;
	new->rcv_nxt_high = rcv_nxt_high;
	INIT_LIST_HEAD(&new->links);
	list_add_tail(&new->links, &ack_que->head);
	if (itv > phi + mu) 
		ack_que->lic++;
}

/*
 * removing the oldest ack from the ack_que 
 */
static void ack_dequeue(struct ack_que *ack_que)
{
	struct ack *first, *second;
	long itv;

	if (list_empty(&ack_que->head)) 
		return;

	first = list_first_entry(&ack_que->head, struct ack, links);
	list_del(&first->links);
	second = list_first_entry(&ack_que->head, struct ack, links);
	itv = second->snt_time_ms - first->snt_time_ms;
	if (itv > phi + mu) 
		ack_que->lic = max_t(int, ack_que->lic - 1, 0);
	kfree(first);
}

/*
 * emptying the ack_que and resetting relevant variables
 */
static void ack_queue_reset(struct ack_que *ack_que)
{
	struct ack *itr, *tmp;

	if (!list_empty(&ack_que->head)) {
		list_for_each_entry_safe(itr, tmp, &ack_que->head, links) {
			list_del(&itr->links);
			kfree(itr);
		}
	}

	INIT_LIST_HEAD(&ack_que->head);
	ack_que->act_wnd = INF_WND;
	ack_que->lic = 0;
}

/*
 * checking rwnd validity
 */
static bool rwnd_is_invalid(struct sock *sk, u32 adv_wnd, u32 act_wnd, int fct)
{
	struct flexir *flexir = get_priv(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	long diff_wnd, thresh;

	if (!flexir->vars->t_last_seg)
		return false;

	adv_wnd = adv_wnd / icsk->icsk_ack.rcv_mss * icsk->icsk_ack.rcv_mss;
	diff_wnd = adv_wnd - act_wnd;
	thresh = epsilon * icsk->icsk_ack.rcv_mss;

	return act_wnd < ((u64)adv_wnd * fct / 100) && diff_wnd > thresh;
}

/*
 * updating actual window and ack_que on the receipt of a data segment
 */
static bool update_awnd_aque(struct sock *sk, u32 tsecr, u32 size)
{
	struct flexir *flexir = get_priv(sk);
	struct ack *first_ack;
	u64 now_ms = tcp_clock_ns() / NSEC_PER_MSEC;
	long dur_freeze;
	bool updated = false;

	if (list_empty(&flexir->vars->ack_que.head)) 
		return updated;
	
	first_ack = list_first_entry(&flexir->vars->ack_que.head, struct ack, links);
	
	if (!time_after32(tsecr, first_ack->tsval)) {
		flexir->vars->ack_que.act_wnd = flexir->vars->rcv_nxt_high - first_ack->rcv_nxt_high;
		if (flexir->vars->state == INC && flexir->vars->freeze.reasons & F_SLM) {
			if (!rwnd_is_invalid(sk, first_ack->adv_wnd, flexir->vars->ack_que.act_wnd, eta)) {
				// quiting sender limited mode as soon as actual window keeps up with advertised window
				flexir->vars->freeze.reasons &= ~F_SLM;
				if (!flexir->vars->freeze.reasons) {
					dur_freeze = now_ms - flexir->vars->freeze.start_ms;
					flexir->vars->freeze.start_ms = 0;
					flexir->vars->t0 += dur_freeze;
				}
			}
		}
		return updated;
	}

	// updating adv_wnd and act_wnd when an RTT has completed
	if (flexir->vars->ack_que.act_wnd != INF_WND) {
		flexir->vars->act_wnd = flexir->vars->ack_que.act_wnd;
		flexir->vars->adv_wnd = first_ack->adv_wnd;
		updated = true;
	}

	// removing old acks from ack_que
	while (!list_empty(&flexir->vars->ack_que.head)) {
		first_ack = list_first_entry(&flexir->vars->ack_que.head, struct ack, links);
		if (time_after32(tsecr, first_ack->tsval)) {
			ack_dequeue(&flexir->vars->ack_que);
		} else {
			break;
		}
	} 

	// updating act_wnd 
	if (!list_empty(&flexir->vars->ack_que.head)) {
		first_ack = list_first_entry(&flexir->vars->ack_que.head, struct ack, links);
		flexir->vars->ack_que.act_wnd = flexir->vars->rcv_nxt_high - first_ack->rcv_nxt_high;
	}
	
	return updated;
}

/*
 * a receiver side RTO estimation. It is basically the same as the sender side algorithm
 */
static u32 get_rto_ms(struct flexir *flexir)
{
	if (!flexir->vars->srtt_ms || !flexir->vars->rttdev_life_max) 
		return 0;
	return (flexir->vars->srtt_ms >> 3) + flexir->vars->rttdev_life_max;
}

// adapted from tcp_rto_min
static u32 get_min_rto_ms(struct sock *sk)
{
	const struct dst_entry *dst = __sk_dst_get(sk);
	u32 rto_min = inet_csk(sk)->icsk_rto_min;

	if (dst && dst_metric_locked(dst, RTAX_RTO_MIN))
		rto_min = dst_metric_rtt(dst, RTAX_RTO_MIN);
	return jiffies_to_msecs(rto_min);
}

// adapted from tcp_rtt_estimator
static void update_rtt_stats(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct flexir *flexir = get_priv(sk);
	u32 srtt = flexir->vars->srtt_ms;
	long m;

	if (flexir->vars->rtt_ms <= 0) 
		return;

	m = flexir->vars->rtt_ms;
	if (srtt != 0) {
		m -= (srtt >> 3);	// m is now deviation 
		srtt += m;		// rtt = 7/8 history + 1/8 new 
		if (m < 0) {
			m = -m;		// m is now abs(deviation) 
			m -= (flexir->vars->rttdev_ms >> 2);   // m is now error in rttdev
			if (m > 0)
				m >>= 3;
		} else {
			m -= (flexir->vars->rttdev_ms >> 2);   // m is now error in rttdev 
		}
		flexir->vars->rttdev_ms += m;		// s_rttdev = 3/4 history + 1/4 new 
		if (flexir->vars->rttdev_ms > flexir->vars->rttdev_round_max) {
			flexir->vars->rttdev_round_max = flexir->vars->rttdev_ms;
			if (flexir->vars->rttdev_round_max > flexir->vars->rttdev_life_max)
				flexir->vars->rttdev_life_max = flexir->vars->rttdev_round_max;
		}
		if (flexir->vars->round_start && !time_before32(tp->rx_opt.rcv_tsecr, flexir->vars->round_start)) {
			if (flexir->vars->rttdev_round_max < flexir->vars->rttdev_life_max)
				flexir->vars->rttdev_life_max -= (flexir->vars->rttdev_life_max - flexir->vars->rttdev_round_max) >> 2;
			flexir->vars->round_start = 0;
			flexir->vars->rttdev_round_max = get_min_rto_ms(sk);
		}
	} else { // no previous measurement 
		srtt = m << 3;		
		flexir->vars->rttdev_ms = m << 1;	// rtt_dev = 2 * rtt_sample
		flexir->vars->rttdev_life_max = max(flexir->vars->rttdev_ms, get_min_rto_ms(sk));
		flexir->vars->rttdev_round_max = flexir->vars->rttdev_life_max;
		flexir->vars->round_start = 0;
	}
	flexir->vars->srtt_ms = max_t(u32, 1 << 3, srtt);
}

/*
 * decreasing rcv_ssthresh 
 */
static void decrease_rcv_ssthresh(struct sock *sk, int dec_reason)
{
	struct flexir *flexir = get_priv(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	u32 min_ssthresh = iota * icsk->icsk_ack.rcv_mss;
	u32 init_ssthresh = READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_rcc_init_rwnd) * tp->advmss;
	u32 new_ssthresh, wnd;

	switch (dec_reason) {
	case INIT_DEC: 
		new_ssthresh = init_ssthresh;
		break;
	case MPRS_DEC:
		new_ssthresh = flexir->vars->memprs_ssthresh;
		break;
	case IDL_DEC:
		new_ssthresh = flexir->vars->last_rwnd >> 1;
		break;
	case VLD_DEC:
		new_ssthresh = (flexir->vars->act_wnd + tp->rcv_ssthresh) >> 1;
		break;
	case LOSS_DEC:
		new_ssthresh = tp->rcv_wnd >> 1;
		break;
	case DELAY_DEC: 
		if ((flexir->vars->act_wnd != INF_WND) && rwnd_is_invalid(sk, flexir->vars->adv_wnd, flexir->vars->act_wnd, zeta)) {
			// decreasing from actual window so that the rate reduction can be effective
			wnd = flexir->vars->act_wnd;
		} else {
			// decreasing from rcv_ssthresh to ensure inter-rtt fairness
			wnd = tp->rcv_ssthresh;
		}
		/*
		 * don't reduce rcv_ssthresh by more than 1/2 
		 */ 
		new_ssthresh = max_t(u32, (u64)wnd * gamma / 100, tp->rcv_ssthresh >> 1);
		break;
	default:
		return;
	}

	// rounding to the closest integer to improve inter-RTT fairness
	new_ssthresh = DIV_ROUND_CLOSEST(new_ssthresh, icsk->icsk_ack.rcv_mss) * icsk->icsk_ack.rcv_mss;
	if (new_ssthresh >= tp->rcv_ssthresh) {
		if (dec_reason == DELAY_DEC) 
			new_ssthresh = max_t(long, tp->rcv_ssthresh - icsk->icsk_ack.rcv_mss, min_ssthresh);
		else 
			new_ssthresh = tp->rcv_ssthresh;
	}
	tp->rcv_ssthresh = max(new_ssthresh, min_ssthresh);
	
	/*
	 * resetting base_rtt when rcv_ssthresh has been reduced to minimum rwnd 
	 */
	if (dec_reason == DELAY_DEC && tp->rcv_ssthresh <= min_ssthresh) {
		if (flexir->vars->rtt_ms > 0)
			flexir->vars->base_rtt = flexir->vars->rtt_ms;
		else
			flexir->vars->base_rtt = MAX_RTT;
	}
	if (dec_reason == IDL_DEC) {
		// resetting base_rtt afger ilde
		flexir->vars->base_rtt = MAX_RTT;
	}
	
	flexir->vars->tsval_dec_done = 0;
	flexir->vars->dec_reason = dec_reason;
	flexir->vars->state = DEC;
}

static void start_timer(struct sock *sk, struct hrtimer *hrt, u64 expires)
{
	hrtimer_start(hrt, ns_to_ktime(expires), HRTIMER_MODE_ABS_PINNED_SOFT);
	sock_hold(sk);
}

static void stop_timer(struct sock *sk, struct hrtimer *hrt)
{
	if (hrtimer_try_to_cancel(hrt) == 1)
		__sock_put(sk);
}

static void check_start_wupd_timer(struct sock *sk, u64 now_ns)
{
	struct flexir *flexir = get_priv(sk);

	if (xi && flexir->vars->base_rtt > phi) 
		start_timer(sk, &flexir->wnd_upd_timer, now_ns + phi * NSEC_PER_MSEC);
}

static void reset_wnd_upd_timer(struct sock *sk)
{
	struct flexir *flexir = get_priv(sk);
	u64 now_ns = tcp_clock_ns();

	if (hrtimer_is_queued(&flexir->wnd_upd_timer))
		stop_timer(sk, &flexir->wnd_upd_timer);
	check_start_wupd_timer(sk, now_ns);
}

// initializing variables used in the increase mode
static void enter_inc(struct sock *sk)
{
	struct flexir *flexir = get_priv(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u64 now_ns = tcp_clock_ns();
	u64 now_ms = now_ns / NSEC_PER_MSEC;
	u64 r0 = 0;

	if (flexir->vars->base_rtt >= MAX_RTT)
		return;

	flexir->vars->t0 = now_ms;
	r0 = (u64)tp->rcv_ssthresh * MSEC_PER_SEC / flexir->vars->base_rtt;
	flexir->vars->exp_term = lamda * TSS;
	flexir->vars->const_term = r0 - flexir->vars->exp_term;
	if (flexir->vars->dec_reason != VLD_DEC)
		flexir->vars->t_cong_alert = 0;
	flexir->vars->memprs_ssthresh = 0;
	flexir->vars->freeze.start_ms = 0;
	flexir->vars->freeze.reasons = 0;
	flexir->vars->t_last_inc = now_ms;
	flexir->vars->dec_reason = TBD;
	check_start_wupd_timer(sk, now_ns);
	flexir->vars->state = INC;
}

// checking if tcp is under memory pressure
static void check_mem_pressure(struct sock *sk, u64 now_ms)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct flexir *flexir = get_priv(sk);
	int unused_mem = sk_unused_reserved_mem(sk);
	long dur_freeze;

	if (tcp_under_memory_pressure(sk)) {
		// the following line is borrowed from __tcp_adjust_rcv_ssthresh()
		flexir->vars->memprs_ssthresh = max_t(u32, min(tp->rcv_ssthresh, MPRS_SEGS * tp->advmss), tcp_win_from_space(sk, unused_mem));
		flexir->vars->memprs_ssthresh = flexir->vars->memprs_ssthresh / icsk->icsk_ack.rcv_mss * icsk->icsk_ack.rcv_mss;
		if (tp->rcv_ssthresh > flexir->vars->memprs_ssthresh) {
			decrease_rcv_ssthresh(sk, MPRS_DEC);
		} else if (tp->rcv_ssthresh == flexir->vars->memprs_ssthresh) {
			if (flexir->vars->state == INC && !(flexir->vars->freeze.reasons & F_MEMPRS)) {
				flexir->vars->freeze.reasons |= F_MEMPRS;
				if (!flexir->vars->freeze.start_ms)
					flexir->vars->freeze.start_ms = max(flexir->vars->t0, flexir->vars->t_last_inc);
			}
		}
	} else {
		if (flexir->vars->state == INC && flexir->vars->freeze.reasons & F_MEMPRS) {
			flexir->vars->freeze.reasons &= ~F_MEMPRS;
			if (!flexir->vars->freeze.reasons) {
				dur_freeze = now_ms - flexir->vars->freeze.start_ms;
				flexir->vars->t0 += dur_freeze;
				flexir->vars->freeze.start_ms = 0;
			}
		}
		flexir->vars->memprs_ssthresh = 0;
	}
}

/* 
 * checking if rcv_ssthresh has been increased to its maximum
 */
static void check_ssthresh_limit(struct sock *sk, u64 now_ms, int *clamp)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct flexir *flexir = get_priv(sk);
	long dur_freeze;

	// we need to round clamp to a multiple of MSS to enable valid comparison between clamp and rcv_ssthresh.
	*clamp = min_t(int, tp->window_clamp, tcp_space(sk)) / icsk->icsk_ack.rcv_mss * icsk->icsk_ack.rcv_mss;
	if (tp->rcv_ssthresh >= *clamp) {
		if (!(flexir->vars->freeze.reasons & F_NOROOM)) {
			flexir->vars->freeze.reasons |= F_NOROOM;
			if (!flexir->vars->freeze.start_ms)
				flexir->vars->freeze.start_ms = max(flexir->vars->t0, flexir->vars->t_last_inc);
		}
	} else {
		if (flexir->vars->freeze.reasons & F_NOROOM) {
			flexir->vars->freeze.reasons &= ~F_NOROOM;
			if (!flexir->vars->freeze.reasons) {
				dur_freeze = now_ms - flexir->vars->freeze.start_ms;
				flexir->vars->t0 += dur_freeze;
				flexir->vars->freeze.start_ms = 0;
			}
		}
	}
}

/* 
 * rate increase function: r = lamda * TSS * (1 + beta / 100) ^ (t / alpha) - lamda * TSS + r0 
 * piecewise linear approximation is used to approximate the exponential increase function
 * the rate function is converted to r = exp_term + const_term + inc
 * where exp_term = lamda * TSS * (1 + beta / 100) ^ floor(t_offset / alpha)
 * const_term = r0 - lamda * TSS 
 * inc = t_offset / alpha * inc_of_interval
 */
static int increase_rcv_ssthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct flexir *flexir = get_priv(sk);
	u64 now_ns = tcp_clock_ns();
	u64 now_ms = now_ns / NSEC_PER_MSEC;
	u64 r;
	s64 t_offset;
	u32 new_ssthresh;
	int clamp;
	
	if (flexir->vars->state != INC) {
		return -1;
	}
	
	check_ssthresh_limit(sk, now_ms, &clamp);
	if (flexir->vars->freeze.reasons)
		return -1;
	
	t_offset = now_ms - flexir->vars->t0;
	if (t_offset < 0) 
		return -1;
	
	while (t_offset > alpha) {
		// advancing t0 by one interval
		flexir->vars->t0 += alpha;
		// exp_term = exp_term * 1.4
		flexir->vars->exp_term += DIV_ROUND_CLOSEST_ULL(flexir->vars->exp_term * beta, 100U);
		t_offset = now_ms - flexir->vars->t0;
	}
	r = flexir->vars->const_term + flexir->vars->exp_term + DIV_ROUND_CLOSEST_ULL(flexir->vars->exp_term * beta * t_offset, alpha * 100U);
	new_ssthresh = min_t(u64, r * flexir->vars->base_rtt / MSEC_PER_SEC, clamp);
	if (flexir->vars->memprs_ssthresh)
		new_ssthresh = min(new_ssthresh, flexir->vars->memprs_ssthresh);
	tp->rcv_ssthresh = max(new_ssthresh / icsk->icsk_ack.rcv_mss * icsk->icsk_ack.rcv_mss, tp->rcv_ssthresh);
	flexir->vars->t_last_inc = now_ms;
	if (ALIGN(tp->rcv_ssthresh, 1 << tp->rx_opt.rcv_wscale) > flexir->vars->last_rwnd) {
		return 0;
	} else { 
		return -1;
	}
}

/*
 * if allowed this function will send out a window update ack. it is called when wnd_upd_timer goes off.
 */
static void try_send_ack(struct sock *sk) {
	struct tcp_sock *tp = tcp_sk(sk);
	struct flexir *flexir = get_priv(sk);
	struct ack *first_ack;
	u64 now_ns = tcp_clock_ns();
	u64 now_ms = now_ns / NSEC_PER_MSEC;
	long dur_idle;

	if (!flexir->vars)
		return;
	
	if (sk->sk_state != TCP_ESTABLISHED && sk->sk_state != TCP_FIN_WAIT1 && sk->sk_state != TCP_FIN_WAIT2)
		return;
	
	check_mem_pressure(sk, now_ms);
	
	if (flexir->vars->state != INC) 
		return;
	
	if (flexir->vars->t_cong_alert) 
		return;
		
	if (list_empty(&flexir->vars->ack_que.head)) 
		return;
	
	first_ack = list_first_entry(&flexir->vars->ack_que.head, struct ack, links);
	if (rwnd_is_invalid(sk, first_ack->adv_wnd, flexir->vars->ack_que.act_wnd, eta)) 
		return;
	
	if (!flexir->vars->ack_que.lic) 
		return;
	
	/*
	 * we need to stop sending window update acks when the connection is possibly idle
	 */ 
	dur_idle = now_ms - flexir->vars->t_last_seg;
	if (dur_idle > flexir->vars->base_rtt) 
		return;
	
	if (!increase_rcv_ssthresh(sk)) {
		tcp_mstamp_refresh(tp);
		__tcp_send_ack(sk, tp->rcv_nxt);
	} 

	check_start_wupd_timer(sk, now_ns);
}

/*
 * wnd_upd_timer handler
 */
static enum hrtimer_restart wnd_upd_timer_handler(struct hrtimer *t) {
	struct sock *sk = hrtimer_to_sk(t, "wnd_upd_timer");

	if (!sk) 
		goto out;

	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		try_send_ack(sk); 
	} else {
		// delaying the handling of timer events
		if (!test_and_set_bit(TCP_WND_UPD_TIMER_DEFERRED, &sk->sk_tsq_flags))
			sock_hold(sk);
	}
	bh_unlock_sock(sk);

	out:
	sock_put(sk);
	return HRTIMER_NORESTART;
}

/*
 * it is called when the wnd_upd_timer handling was deferred 
 */
static void tcp_flexir_wnd_upd_timer_deferred(struct sock *sk) 
{
	struct flexir *flexir = get_priv(sk);

	if (!flexir->vars) 
		return;

	try_send_ack(sk);
}

/*
 * checking whether the sending rate is limited by rwnd
 */
static void check_rate_validate_rwnd(struct sock *sk)
{
	struct flexir *flexir = get_priv(sk);
	struct ack *first_ack;
	u64 now_ms = tcp_clock_ns() / NSEC_PER_MSEC;
	u32 rto_ms = get_rto_ms(flexir);
	long dur_ivld, dur_cong, dur_freeze;
	
	if (!rto_ms)
		return;
	
	if (list_empty(&flexir->vars->ack_que.head)) 
		return;
	
	first_ack = list_first_entry(&flexir->vars->ack_que.head, struct ack, links);
	// ignoring invalid data
	if (flexir->vars->tsval_dec_done && !time_after32(first_ack->tsval, flexir->vars->tsval_dec_done)) 
		return;
	
	if (rwnd_is_invalid(sk, flexir->vars->adv_wnd, flexir->vars->act_wnd, eta)) { 
		if (!(flexir->vars->freeze.reasons & F_SLM)) { 
			// freezing rwnd when rate is no longer limited by rwnd
			flexir->vars->t_invalid_rwnd = max(flexir->vars->t0, flexir->vars->t_last_inc);
			flexir->vars->freeze.reasons |= F_SLM;
			if (!flexir->vars->freeze.start_ms) {
				flexir->vars->freeze.start_ms = flexir->vars->t_invalid_rwnd;
			}
		} 
		dur_ivld = now_ms - flexir->vars->t_invalid_rwnd;

		if (flexir->vars->t_cong_alert) 
			dur_cong = now_ms - flexir->vars->t_cong_alert;
		else
			dur_cong = 0;
		// decreasing rwnd when rwnd is invalid for at least one RTO or rwnd is being frozen due to high queuing delay
		if (dur_ivld > rto_ms || dur_cong > theta) 
			decrease_rcv_ssthresh(sk, VLD_DEC);
	} else { 
		if (flexir->vars->freeze.reasons & F_SLM) { 
			// resuming rate increase when rate becomes limited by rwnd again
			flexir->vars->t_invalid_rwnd = 0;
			flexir->vars->freeze.reasons &= ~F_SLM;
			if (!flexir->vars->freeze.reasons) {
				dur_freeze = now_ms - flexir->vars->freeze.start_ms;
				flexir->vars->t0 += dur_freeze;
				flexir->vars->freeze.start_ms = 0;
			}
		}
	}
}

/*
 * validating rwnd after idle
 */
static void check_idle_validate_rwnd(struct sock *sk)
{
	struct flexir *flexir = get_priv(sk);
	u64 now_ms = tcp_clock_ns() / NSEC_PER_MSEC;
	u32 rto_ms = get_rto_ms(flexir);
	long dur_idle;

	if (!rto_ms)
		return;

	dur_idle = flexir->vars->t_last_seg ? now_ms - flexir->vars->t_last_seg : 0;
	if (dur_idle > rto_ms) { 
		decrease_rcv_ssthresh(sk, IDL_DEC);
		return;
	} 
}

// flexir doesn't have its own loss detector. It assumes loss when it receives a retransmission 
static int classify_seg(struct sock *sk, const struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_options_received rx_opt;
	struct rb_node *itr, *next;
	struct sk_buff *skb_node;
	u32 seq = TCP_SKB_CB(skb)->seq;
	u32 end_seq = TCP_SKB_CB(skb)->end_seq;
	int class;

	if (!RB_EMPTY_ROOT(&tp->out_of_order_queue) || after(seq, tp->rcv_nxt)) { 
		if (RB_EMPTY_ROOT(&tp->out_of_order_queue)) {
			// the first reordered segment received
			return OUTORD;
		}
		if (before(seq, tp->rcv_nxt)) {
			// partial old partial new
			return RETRANS;
		}
		itr = rb_first(&tp->out_of_order_queue);
		skb_node = rb_to_skb(itr);
		if (!after(end_seq, TCP_SKB_CB(skb_node)->seq)) {
			// non-overlapping, before the first reordered segment
			tcp_parse_options(sock_net(sk), skb_node, &rx_opt, 0, NULL);
			if (time_after32(tp->rx_opt.rcv_tsval, rx_opt.rcv_tsval)) {
				return RETRANS;
			} else {
				return OUTORD;
			}
		}
		itr = rb_last(&tp->out_of_order_queue);
		skb_node = rb_to_skb(itr);
		if (!before(seq, TCP_SKB_CB(skb_node)->end_seq)) { 
			// non-overlapping, after the last reordered segment
			return OUTORD;
		}
		// we need to traverse the out of order tree
		itr = tp->out_of_order_queue.rb_node;
		while (itr) {
			skb_node = rb_to_skb(itr);
			if (!after(end_seq, TCP_SKB_CB(skb_node)->seq)) {
				// non-overlapping, before the tree node
				if (!itr->rb_left) {
					tcp_parse_options(sock_net(sk), skb_node, &rx_opt, 0, NULL);
					if (time_after32(tp->rx_opt.rcv_tsval, rx_opt.rcv_tsval)) {
						class = RETRANS;
					} else {
						class = OUTORD;
					}
				}
				next = itr;
				itr = itr->rb_left;
				continue;
			}
			if (before(seq, TCP_SKB_CB(skb_node)->seq)) {
				// partial overlapping (the segment has smaller seqno)
				class = RETRANS;
				break;
			}
			if (!after(end_seq, TCP_SKB_CB(skb_node)->end_seq)) {
				// full overlapping
				class = DUP;
				break;
			}
			if ((before(seq, TCP_SKB_CB(skb_node)->end_seq))) {
				// partial overlapping (the segment has larger seqno)
				class = RETRANS;
				break;
			}
			// non-overlapping, after the tree node
			if (!itr->rb_right) {
				skb_node = rb_to_skb(next);
				tcp_parse_options(sock_net(sk), skb_node, &rx_opt, 0, NULL);
				if (time_after32(tp->rx_opt.rcv_tsval, rx_opt.rcv_tsval)) {
					class = RETRANS;
				} else {
					class = OUTORD;
				}
			}
			itr = itr->rb_right;
		}
		return class;
	} else { // in order arrival
		return INORD;
	}
}

/*
 * calculating rtt using timestamp values. using every full-sized segment to ensure fairness
 */
static void cal_rtt(struct sock *sk, u32 len, int class)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct flexir *flexir = get_priv(sk);
	u32 rtt_ts;
	int diff_tsval = 0;
	
	if (class == DUP) {
		flexir->vars->rtt_ms = -1;
		return;
	}
		
	if (len >= inet_csk(sk)->icsk_ack.rcv_mss) {
		rtt_ts = tcp_time_stamp_ts(tp) - tp->rx_opt.rcv_tsecr;
		if (likely(rtt_ts < INT_MAX / (MSEC_PER_SEC / TCP_TS_HZ))) {
			if (!rtt_ts)
				rtt_ts = 1;
			flexir->vars->rtt_ms = rtt_ts * (MSEC_PER_SEC / TCP_TS_HZ);
			if (flexir->vars->seg_ts.tsecr && tp->rx_opt.rcv_tsecr == flexir->vars->seg_ts.tsecr) {
				// removing delay not caused by forward direction queues
				diff_tsval = max_t(int, tp->rx_opt.rcv_tsval - flexir->vars->seg_ts.tsval, 0);
				flexir->vars->rtt_ms = max_t(int, flexir->vars->rtt_ms - diff_tsval, flexir->vars->base_rtt);
			}
		} else {
			flexir->vars->rtt_ms = -1;
		}
	} else {
		flexir->vars->rtt_ms = -1;
	}
	
	if (tp->rx_opt.rcv_tsecr != flexir->vars->seg_ts.tsecr) {
		flexir->vars->seg_ts.tsval = tp->rx_opt.rcv_tsval;
		flexir->vars->seg_ts.tsecr = tp->rx_opt.rcv_tsecr;
	} else {
		if (time_before32(tp->rx_opt.rcv_tsval, flexir->vars->seg_ts.tsval)) 
			flexir->vars->seg_ts.tsval = tp->rx_opt.rcv_tsval;
	}
}

static void update_base_rtt(struct sock *sk)
{
	struct flexir *flexir = get_priv(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u64 diff_rate;
	u32 old_bd = flexir->vars->base_rtt;

	if (flexir->vars->rtt_ms <= 0)
		return;

	if (flexir->vars->rtt_ms < flexir->vars->base_rtt) {
		flexir->vars->base_rtt = flexir->vars->rtt_ms;
		if (flexir->vars->state == INC) {
			// lifting rate curve along the y axis when base_rtt gets smaller 
			diff_rate = (u64)tp->rcv_ssthresh * MSEC_PER_SEC / flexir->vars->base_rtt - (u64)tp->rcv_ssthresh * MSEC_PER_SEC / old_bd;
			flexir->vars->const_term += diff_rate;
		}
	}
}

static void detect_congestion(struct sock *sk) 
{
	struct flexir *flexir = get_priv(sk);
	u64 now_ms = tcp_clock_ns() / NSEC_PER_MSEC;
	long dur_cong, dur_freeze;
	
	if (flexir->vars->rtt_ms >= flexir->vars->base_rtt + delta) {
		if (!flexir->vars->t_cong_alert) {
			flexir->vars->t_cong_alert = now_ms;
		} else {
			dur_cong = now_ms - flexir->vars->t_cong_alert;
			if (dur_cong >= tau) {
				decrease_rcv_ssthresh(sk, DELAY_DEC);
			} else if (dur_cong >= theta && flexir->vars->state == INC)
				if (!(flexir->vars->freeze.reasons & F_CNG)) { 
					flexir->vars->freeze.reasons |= F_CNG;
					if (!flexir->vars->freeze.start_ms) {
						flexir->vars->freeze.start_ms = max(flexir->vars->t0, flexir->vars->t_last_inc);
					}
				} 
		}
	} else {
		if (flexir->vars->state == INC && flexir->vars->freeze.reasons & F_CNG) { 
			flexir->vars->freeze.reasons &= ~F_CNG;
			if (!flexir->vars->freeze.reasons) {
				dur_freeze = now_ms - flexir->vars->freeze.start_ms;
				flexir->vars->t0 += dur_freeze;
				flexir->vars->freeze.start_ms = 0;
			}
		}
		flexir->vars->t_cong_alert = 0;

	}
}

/*************************************************************
 ********************* Interface functions *******************
 ************************************************************/
/*
 * initializing variables
 */
static int tcp_flexir_init(struct sock *sk)
{
	struct flexir *flexir = get_priv(sk);

	flexir->vars = kzalloc(sizeof(struct vars), GFP_KERNEL);
	if (unlikely(!flexir->vars)) 
		return -1;
	
	flexir->vars->freeze.start_ms = 0;
	flexir->vars->freeze.reasons = 0;
	flexir->vars->seg_ts.tsecr = 0;
	flexir->vars->seg_ts.tsval = 0;
	flexir->vars->t_cong_alert = 0;
	flexir->vars->t_last_inc = 0;
	flexir->vars->t_last_seg = 0;
	flexir->vars->t_invalid_rwnd = 0;
	flexir->vars->t0 = 0;
	flexir->vars->const_term = 0;
	flexir->vars->exp_term = 0;
	flexir->vars->memprs_ssthresh = 0;
	flexir->vars->rtt_ms = -1;
	flexir->vars->base_rtt = MAX_RTT;
	flexir->vars->srtt_ms = 0;
	flexir->vars->rttdev_ms = 0;
	flexir->vars->rttdev_round_max = 0;
	flexir->vars->rttdev_life_max = 0;
	flexir->vars->round_start = 0;
	flexir->vars->act_wnd = 0;
	flexir->vars->adv_wnd = 0;
    flexir->vars->last_rwnd = 0;
	flexir->vars->tsval_dec_done = 0;
	flexir->vars->rcv_nxt_high = 0;
	flexir->vars->edge_seq = 0;
	flexir->vars->state = INIT;
	flexir->vars->dec_reason = TBD;
	flexir->vars->seen_fst_ack = false;

	INIT_LIST_HEAD(&flexir->vars->ack_que.head);
	flexir->vars->ack_que.act_wnd = INF_WND;
	flexir->vars->ack_que.lic = 0;

	hrtimer_init(&flexir->wnd_upd_timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_PINNED_SOFT);
	flexir->wnd_upd_timer.function = wnd_upd_timer_handler;

	return 0;
}

// necessary operations when a data segment arrives
static void tcp_flexir_data_arr(struct sock *sk, const struct sk_buff *skb) 
{
	struct flexir *flexir = get_priv(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u64 now_ms = tcp_clock_ns() / NSEC_PER_MSEC;
	u32 seq = TCP_SKB_CB(skb)->seq;
	u32 end_seq = TCP_SKB_CB(skb)->end_seq;
	u32 len = end_seq - seq;
	long dur_freeze;
	bool updated;
	int class;

	if (!flexir->vars) {
		return;
	}
	
	if (!len) 
		return;
	
	if (after(end_seq, flexir->vars->rcv_nxt_high)) {
		flexir->vars->rcv_nxt_high = end_seq;
	}
	
	if (flexir->vars->state == INC) 
		reset_wnd_upd_timer(sk);

	check_mem_pressure(sk, now_ms);
	
	check_idle_validate_rwnd(sk);
	
	class = classify_seg(sk, skb);

	cal_rtt(sk, len, class);
	update_base_rtt(sk); 
	update_rtt_stats(sk);
	updated = update_awnd_aque(sk, tp->rx_opt.rcv_tsecr, len);
	
    if (flexir->vars->state == INIT) {
		if (tp->advmss && tp->rcv_ssthresh / tp->advmss > READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_rcc_init_rwnd)) {
			decrease_rcv_ssthresh(sk, INIT_DEC);
		} else {
			enter_inc(sk);
		}
	}
	if (class == RETRANS && !(flexir->vars->state == DEC && flexir->vars->dec_reason == LOSS_DEC)) {
		if (!flexir->vars->edge_seq || after(end_seq, flexir->vars->edge_seq)) 
			decrease_rcv_ssthresh(sk, LOSS_DEC);
	}
	if ((flexir->vars->state == DEC) && flexir->vars->tsval_dec_done && !time_before32(tp->rx_opt.rcv_tsecr, flexir->vars->tsval_dec_done)) {
		if (flexir->vars->dec_reason == LOSS_DEC) 
			flexir->vars->edge_seq = flexir->vars->rcv_nxt_high;
		enter_inc(sk);
	}
	if (flexir->vars->rtt_ms > 0 && (flexir->vars->state == INC || (flexir->vars->state == DEC && flexir->vars->dec_reason == VLD_DEC))) 
		detect_congestion(sk);
	if (updated && flexir->vars->state == INC) 
		check_rate_validate_rwnd(sk);
	if (class == INORD) {
		if (flexir->vars->state == INC && (flexir->vars->freeze.reasons & F_OFO)) { 
			flexir->vars->freeze.reasons &= ~F_OFO;
			if (!flexir->vars->freeze.reasons) {
				dur_freeze = now_ms - flexir->vars->freeze.start_ms;
				flexir->vars->t0 += dur_freeze;
				flexir->vars->freeze.start_ms = 0;
			}
		}
	} else if (class == OUTORD) { // stop increasing rwnd when segments don't arrive in order
		if (flexir->vars->state == INC && !(flexir->vars->freeze.reasons & F_OFO)) {
			flexir->vars->freeze.reasons |= F_OFO;
			if (!flexir->vars->freeze.start_ms) {
				flexir->vars->freeze.start_ms = max(flexir->vars->t0, flexir->vars->t_last_inc);
			}
		}
	}

	flexir->vars->t_last_seg = now_ms;
}

// Only growing window when TCP allows
static void tcp_flexir_grow_window(struct sock *sk, const struct sk_buff *skb, bool adjust)
{
	struct flexir *flexir = get_priv(sk);
	u64 now_ms = tcp_clock_ns() / NSEC_PER_MSEC;
	long dur_cong;

	if (!flexir->vars) {
		return;
	}

	if (flexir->vars->state != INC)
		return;
	
	if (flexir->vars->rtt_ms <= 0 && flexir->vars->t_cong_alert) {
		dur_cong = now_ms - flexir->vars->t_cong_alert;
		if (dur_cong >= theta) {
			return;
		}
	}
	
	increase_rcv_ssthresh(sk);
}

// necessary operations when an ack is sent
static void tcp_flexir_ack_sent(struct sock *sk, u32 ack_tsval) 
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct flexir *flexir = get_priv(sk);
	u64 now_ns = tcp_clock_ns();
	u64 now_ms = now_ns / NSEC_PER_MSEC;

	if (!flexir->vars)
		return;
	
	if (flexir->vars->state == DEC) 
		if (!flexir->vars->tsval_dec_done && tp->rcv_wnd <= ALIGN(tp->rcv_ssthresh, 1 << tp->rx_opt.rcv_wscale)) {
			flexir->vars->tsval_dec_done = ack_tsval - tp->tsoffset;
	}

	if (!flexir->vars->round_start)
		flexir->vars->round_start = ack_tsval - tp->tsoffset;
	
	// initializing rcv_nxt_high
	if (unlikely(!flexir->vars->seen_fst_ack)) {
		flexir->vars->seen_fst_ack = true;
		if (tp->ooo_last_skb)
			flexir->vars->rcv_nxt_high = TCP_SKB_CB(tp->ooo_last_skb)->end_seq;
		else
			flexir->vars->rcv_nxt_high = tp->rcv_nxt;
	}
	ack_enqueue(&flexir->vars->ack_que, now_ms, ack_tsval - tp->tsoffset, tp->rcv_wnd, flexir->vars->rcv_nxt_high);

	flexir->vars->last_rwnd = tp->rcv_wnd;
}

static void tcp_flexir_release(struct sock *sk)
{
	struct flexir *flexir = get_priv(sk);

	if (!flexir->vars) {
		return;
	}
	stop_timer(sk, &flexir->wnd_upd_timer);
	ack_queue_reset(&flexir->vars->ack_que);
	kfree(flexir->vars);
}

static struct tcp_rcv_cc_ops tcp_flexir __read_mostly = {
		.init = tcp_flexir_init, 
		.data_arr = tcp_flexir_data_arr, 
		.grow_window = tcp_flexir_grow_window, 
		.ack_sent = tcp_flexir_ack_sent, 
		.wnd_upd_timer_deferred = tcp_flexir_wnd_upd_timer_deferred, 
		.release = tcp_flexir_release, 
		.owner = THIS_MODULE,
		.name = "flexir"
};

static int __init tcp_flexir_register(void)
{
	BUILD_BUG_ON(sizeof(struct flexir) > RCV_CC_PRIV_SIZE);

	return tcp_register_rcv_cc(&tcp_flexir);
}

static void __exit tcp_flexir_unregister(void)
{
	tcp_unregister_rcv_cc(&tcp_flexir);
}

module_init(tcp_flexir_register);
module_exit(tcp_flexir_unregister);

MODULE_AUTHOR("Qian Li");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP FlexiR -- A Flexible Receiver side LBE CCA for TCP");
