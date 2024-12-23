module core_l1d_l1i_64 (
	clk,
	reset,
	syscall_emu,
	core_state,
	l1i_state,
	l1d_state,
	l2_state,
	mmu_state,
	rob_ptr,
	memq_empty,
	putchar_fifo_out,
	putchar_fifo_empty,
	putchar_fifo_pop,
	putchar_fifo_wptr,
	putchar_fifo_rptr,
	took_exc,
	paging_active,
	page_table_root,
	extern_irq,
	in_flush_mode,
	resume,
	resume_pc,
	ready_for_resume,
	mem_req_valid,
	mem_req_addr,
	mem_req_tag,
	mem_req_store_data,
	mem_req_opcode,
	mem_rsp_valid,
	mem_req_gnt,
	mem_rsp_tag,
	mem_rsp_load_data,
	alloc_valid,
	alloc_two_valid,
	iq_one_valid,
	iq_none_valid,
	in_branch_recovery,
	retire_reg_ptr,
	retire_reg_data,
	retire_reg_valid,
	retire_reg_two_ptr,
	retire_reg_two_data,
	retire_reg_two_valid,
	retire_valid,
	retire_two_valid,
	rob_empty,
	retire_pc,
	retire_two_pc,
	branch_pc,
	branch_pc_valid,
	branch_fault,
	l1i_cache_accesses,
	l1i_cache_hits,
	l1d_cache_accesses,
	l1d_cache_hits,
	l2_cache_accesses,
	l2_cache_hits,
	l1i_tlb_accesses,
	l1i_tlb_hits,
	l1d_tlb_accesses,
	l1d_tlb_hits,
	monitor_ack,
	took_irq,
	got_break,
	got_ud,
	got_bad_addr,
	got_monitor,
	inflight,
	epc,
	restart_ack,
	priv
);
	reg _sv2v_0;
	localparam L1D_CL_LEN = 16;
	localparam L1D_CL_LEN_BITS = 128;
	input wire clk;
	input wire reset;
	input wire syscall_emu;
	output wire [4:0] core_state;
	output wire [3:0] l1i_state;
	output wire [3:0] l1d_state;
	output wire [4:0] l2_state;
	output wire [3:0] mmu_state;
	output wire [4:0] rob_ptr;
	output wire memq_empty;
	output wire [7:0] putchar_fifo_out;
	output wire putchar_fifo_empty;
	input wire putchar_fifo_pop;
	output wire [3:0] putchar_fifo_wptr;
	output wire [3:0] putchar_fifo_rptr;
	output wire took_exc;
	output wire paging_active;
	output wire [63:0] page_table_root;
	input wire extern_irq;
	input wire resume;
	input wire [63:0] resume_pc;
	output wire in_flush_mode;
	output wire ready_for_resume;
	output wire [63:0] branch_pc;
	output wire branch_pc_valid;
	output wire branch_fault;
	output wire [63:0] l1i_cache_accesses;
	output wire [63:0] l1i_cache_hits;
	output wire [63:0] l1d_cache_accesses;
	output wire [63:0] l1d_cache_hits;
	output wire [63:0] l2_cache_accesses;
	output wire [63:0] l2_cache_hits;
	output wire [63:0] l1i_tlb_accesses;
	output wire [63:0] l1i_tlb_hits;
	output wire [63:0] l1d_tlb_accesses;
	output wire [63:0] l1d_tlb_hits;
	output wire mem_req_valid;
	output wire [31:0] mem_req_addr;
	output wire [1:0] mem_req_tag;
	output wire [127:0] mem_req_store_data;
	output wire [3:0] mem_req_opcode;
	input wire mem_rsp_valid;
	input wire mem_req_gnt;
	input wire [1:0] mem_rsp_tag;
	input wire [127:0] mem_rsp_load_data;
	output wire alloc_valid;
	output wire alloc_two_valid;
	output wire iq_one_valid;
	output wire iq_none_valid;
	output wire in_branch_recovery;
	output wire [4:0] retire_reg_ptr;
	output wire [63:0] retire_reg_data;
	output wire retire_reg_valid;
	output wire [4:0] retire_reg_two_ptr;
	output wire [63:0] retire_reg_two_data;
	output wire retire_reg_two_valid;
	output wire retire_valid;
	output wire retire_two_valid;
	output wire rob_empty;
	output wire [63:0] retire_pc;
	output wire [63:0] retire_two_pc;
	input wire monitor_ack;
	output wire took_irq;
	output wire got_break;
	output wire got_ud;
	output wire got_bad_addr;
	output wire got_monitor;
	output wire [5:0] inflight;
	output wire [63:0] epc;
	output wire restart_ack;
	output wire [1:0] priv;
	wire [63:0] restart_pc;
	wire [63:0] restart_src_pc;
	wire restart_src_is_indirect;
	wire restart_valid;
	wire [15:0] branch_pht_idx;
	wire took_branch;
	wire [63:0] t_branch_pc;
	wire [63:0] t_target_pc;
	wire t_branch_pc_valid;
	wire t_branch_pc_is_indirect;
	wire t_branch_fault;
	assign branch_pc = t_branch_pc;
	assign branch_pc_valid = t_branch_pc_valid;
	assign branch_fault = t_branch_fault;
	wire retired_call;
	wire retired_ret;
	wire retired_rob_ptr_valid;
	wire retired_rob_ptr_two_valid;
	wire [4:0] retired_rob_ptr;
	wire [4:0] retired_rob_ptr_two;
	wire head_of_rob_ptr_valid;
	wire [4:0] w_head_of_rob_ptr;
	assign rob_ptr = w_head_of_rob_ptr;
	wire flush_req_l1i;
	wire flush_req_l1d;
	wire flush_cl_req;
	wire [63:0] flush_cl_addr;
	wire l1d_flush_complete;
	wire l1i_flush_complete;
	wire [230:0] core_mem_req;
	wire [147:0] core_mem_rsp;
	wire [68:0] core_store_data;
	wire core_mem_req_valid;
	wire core_mem_req_ack;
	wire core_mem_rsp_valid;
	wire core_store_data_valid;
	wire core_store_data_ack;
	wire [63:0] w_mtimecmp;
	wire w_mtimecmp_val;
	reg [2:0] n_flush_state;
	reg [2:0] r_flush_state;
	reg r_flush;
	reg n_flush;
	reg r_flush_l2;
	reg n_flush_l2;
	wire w_l2_flush_complete;
	assign in_flush_mode = r_flush;
	always @(posedge clk)
		if (reset) begin
			r_flush_state <= 3'd0;
			r_flush <= 1'b0;
			r_flush_l2 <= 1'b0;
		end
		else begin
			r_flush_state <= n_flush_state;
			r_flush <= n_flush;
			r_flush_l2 <= n_flush_l2;
		end
	always @(*) begin
		if (_sv2v_0)
			;
		n_flush_state = r_flush_state;
		n_flush = r_flush;
		n_flush_l2 = 1'b0;
		case (r_flush_state)
			3'd0:
				if (flush_req_l1i && flush_req_l1d) begin
					n_flush_state = 3'd1;
					n_flush = 1'b1;
				end
				else if (flush_req_l1i && !flush_req_l1d) begin
					n_flush_state = 3'd2;
					n_flush = 1'b1;
				end
				else if (!flush_req_l1i && flush_req_l1d) begin
					n_flush_state = 3'd3;
					n_flush = 1'b1;
				end
			3'd1:
				if (l1d_flush_complete && !l1i_flush_complete)
					n_flush_state = 3'd2;
				else if (!l1d_flush_complete && l1i_flush_complete)
					n_flush_state = 3'd3;
				else if (l1d_flush_complete && l1i_flush_complete) begin
					$display("flush l2");
					n_flush_state = 3'd4;
					n_flush_l2 = 1'b1;
				end
			3'd2:
				if (l1i_flush_complete) begin
					$display("flush l2");
					n_flush_state = 3'd4;
					n_flush_l2 = 1'b1;
				end
			3'd3:
				if (l1d_flush_complete) begin
					$display("flush l2");
					n_flush_state = 3'd4;
					n_flush_l2 = 1'b1;
				end
			3'd4:
				if (w_l2_flush_complete) begin
					$display("L2 FLUSH COMPLETE");
					n_flush = 1'b0;
					n_flush_state = 3'd0;
				end
			default:
				;
		endcase
	end
	wire l1d_mem_rsp_valid;
	wire l1i_mem_rsp_valid;
	wire l1d_mem_req_ack;
	wire l1d_mem_req_valid;
	wire l1d_mem_req_uc;
	wire [168:0] l1d_mem_req;
	wire [3:0] w_l1d_mem_rsp_tag;
	wire w_l1d_mem_rsp_writeback;
	wire [31:0] w_l1d_mem_rsp_addr;
	wire l1i_mem_req_valid;
	wire [31:0] l1i_mem_req_addr;
	wire [3:0] l1i_mem_req_opcode;
	wire insn_valid;
	wire insn_valid2;
	wire insn_ack;
	wire insn_ack2;
	wire [177:0] insn;
	wire [177:0] insn2;
	wire w_l1_mem_req_ack;
	wire [127:0] w_l1_mem_load_data;
	wire w_mode64;
	wire w_paging_active;
	wire [1:0] w_priv;
	wire [63:0] w_page_table_root;
	assign priv = w_priv;
	wire w_mmu_req_valid;
	wire w_mmu_req_store;
	wire [31:0] w_mmu_req_addr;
	wire [63:0] w_mmu_req_data;
	wire [63:0] w_mmu_rsp_data;
	wire w_mmu_rsp_valid;
	wire w_mmu_gnt_l1i;
	wire w_mmu_gnt_l1d;
	wire [63:0] w_l1d_page_walk_req_va;
	wire w_l1d_page_walk_req_valid;
	wire w_page_fault;
	wire w_l1d_rsp_valid;
	wire w_l1i_rsp_valid;
	wire w_mem_mark_valid;
	wire w_mem_mark_accessed;
	wire w_mem_mark_dirty;
	wire [63:0] w_mem_mark_addr;
	wire w_mem_mark_rsp_valid;
	wire [71:0] page_walk_rsp;
	wire w_restart_complete;
	wire w_l2_l1d_rdy;
	wire drain_ds_complete;
	wire [31:0] dead_rob_mask;
	assign page_table_root = w_page_table_root;
	assign paging_active = w_paging_active;
	wire w_clear_tlb;
	wire w_l2_probe_val;
	wire w_l2_probe_ack;
	wire [31:0] w_l2_probe_addr;
	wire [63:0] w_l1i_tlb_accesses;
	wire [63:0] w_l1i_tlb_hits;
	wire [63:0] w_l1d_tlb_accesses;
	wire [63:0] w_l1d_tlb_hits;
	assign l1i_tlb_accesses = w_l1i_tlb_accesses;
	assign l1i_tlb_hits = w_l1i_tlb_hits;
	assign l1d_tlb_accesses = w_l1d_tlb_accesses;
	assign l1d_tlb_hits = w_l1d_tlb_hits;
	reg [639:0] t_counters;
	always @(*) begin
		if (_sv2v_0)
			;
		t_counters[639-:64] = w_l1i_tlb_hits;
		t_counters[575-:64] = w_l1i_tlb_accesses;
		t_counters[511-:64] = w_l1d_tlb_hits;
		t_counters[447-:64] = w_l1d_tlb_accesses;
		t_counters[383-:64] = l1d_cache_hits;
		t_counters[319-:64] = l1d_cache_accesses;
		t_counters[255-:64] = l1i_cache_hits;
		t_counters[191-:64] = l1i_cache_accesses;
		t_counters[127-:64] = l2_cache_hits;
		t_counters[63-:64] = l2_cache_accesses;
	end
	wire w_mem_req_valid;
	wire [31:0] w_mem_req_addr;
	wire [1:0] w_mem_req_tag;
	wire [127:0] w_mem_req_store_data;
	wire [3:0] w_mem_req_opcode;
	localparam LG_REQ_Q_SZ = 2;
	reg [165:0] mem_fifo [7:0];
	reg [165:0] t_mem_fifo;
	reg [3:0] r_mem_head_ptr;
	reg [3:0] n_mem_head_ptr;
	reg [3:0] r_mem_tail_ptr;
	reg [3:0] n_mem_tail_ptr;
	wire [LG_REQ_Q_SZ:0] w_mem_head_ptr = r_mem_head_ptr[LG_REQ_Q_SZ:0];
	wire [LG_REQ_Q_SZ:0] w_mem_tail_ptr = r_mem_tail_ptr[LG_REQ_Q_SZ:0];
	wire w_mem_empty = r_mem_head_ptr == r_mem_tail_ptr;
	wire w_mem_full = (r_mem_head_ptr != r_mem_tail_ptr) & (r_mem_head_ptr[LG_REQ_Q_SZ:0] == r_mem_tail_ptr[LG_REQ_Q_SZ:0]);
	reg [LG_REQ_Q_SZ:0] r_inflight;
	reg [LG_REQ_Q_SZ:0] n_inflight;
	always @(posedge clk) r_inflight <= (reset ? 'd0 : n_inflight);
	always @(*) begin
		if (_sv2v_0)
			;
		n_inflight = r_inflight;
		if (w_mem_req_valid & !mem_rsp_valid)
			n_inflight = r_inflight + 'd1;
		else if (!w_mem_req_valid & mem_rsp_valid)
			n_inflight = r_inflight - 'd1;
	end
	always @(*) begin
		if (_sv2v_0)
			;
		t_mem_fifo[165-:32] = w_mem_req_addr;
		t_mem_fifo[133-:2] = w_mem_req_tag;
		t_mem_fifo[131-:128] = w_mem_req_store_data;
		t_mem_fifo[3-:4] = w_mem_req_opcode;
		n_mem_tail_ptr = r_mem_tail_ptr;
		n_mem_head_ptr = r_mem_head_ptr;
		if (w_mem_req_valid)
			n_mem_tail_ptr = r_mem_tail_ptr + 'd1;
		if (mem_req_gnt)
			n_mem_head_ptr = r_mem_head_ptr + 'd1;
	end
	always @(posedge clk) begin
		r_mem_tail_ptr <= (reset ? 'd0 : n_mem_tail_ptr);
		r_mem_head_ptr <= (reset ? 'd0 : n_mem_head_ptr);
		if (w_mem_req_valid)
			mem_fifo[w_mem_tail_ptr] <= t_mem_fifo;
	end
	assign got_bad_addr = 1'b0;
	assign mem_req_valid = w_mem_empty == 1'b0;
	assign mem_req_addr = mem_fifo[w_mem_head_ptr][165-:32];
	assign mem_req_tag = mem_fifo[w_mem_head_ptr][133-:2];
	assign mem_req_store_data = mem_fifo[w_mem_head_ptr][131-:128];
	assign mem_req_opcode = mem_fifo[w_mem_head_ptr][3-:4];
	wire w_l2_empty;
	l2_2way l2cache(
		.clk(clk),
		.reset(reset),
		.paging_active(w_paging_active),
		.l2_state(l2_state),
		.l2_probe_val(w_l2_probe_val),
		.l2_probe_addr(w_l2_probe_addr),
		.l2_probe_ack(w_l2_probe_ack),
		.l1d_rdy(w_l2_l1d_rdy),
		.l1d_req_valid(l1d_mem_req_valid),
		.l1d_req(l1d_mem_req),
		.l1i_req(l1i_mem_req_valid),
		.l1i_addr(l1i_mem_req_addr),
		.l1d_rsp_valid(l1d_mem_rsp_valid),
		.l1d_rsp_tag(w_l1d_mem_rsp_tag),
		.l1d_rsp_writeback(w_l1d_mem_rsp_writeback),
		.l1d_rsp_addr(w_l1d_mem_rsp_addr),
		.l1i_rsp_valid(l1i_mem_rsp_valid),
		.l1i_flush_req(flush_req_l1i),
		.l1d_flush_req(flush_req_l1d),
		.l1i_flush_complete(l1i_flush_complete),
		.l1d_flush_complete(l1d_flush_complete),
		.flush_complete(w_l2_flush_complete),
		.l1_mem_req_ack(w_l1_mem_req_ack),
		.l1_mem_load_data(w_l1_mem_load_data),
		.mem_req_valid(w_mem_req_valid),
		.mem_req_addr(w_mem_req_addr),
		.mem_req_tag(w_mem_req_tag),
		.mem_req_store_data(w_mem_req_store_data),
		.mem_req_opcode(w_mem_req_opcode),
		.mem_rsp_valid(mem_rsp_valid),
		.mem_rsp_tag(mem_rsp_tag),
		.mem_rsp_load_data(mem_rsp_load_data),
		.mmu_req_valid(w_mmu_req_valid),
		.mmu_req_addr(w_mmu_req_addr),
		.mmu_req_data(w_mmu_req_data),
		.mmu_req_store(w_mmu_req_store),
		.mmu_rsp_valid(w_mmu_rsp_valid),
		.mmu_rsp_data(w_mmu_rsp_data),
		.mem_mark_valid(w_mem_mark_valid),
		.mem_mark_accessed(w_mem_mark_accessed),
		.mem_mark_dirty(w_mem_mark_dirty),
		.mem_mark_addr(w_mem_mark_addr),
		.mem_mark_rsp_valid(w_mem_mark_rsp_valid),
		.cache_accesses(l2_cache_accesses),
		.cache_hits(l2_cache_hits),
		.l2_empty(w_l2_empty)
	);
	nu_l1d dcache(
		.clk(clk),
		.reset(reset),
		.priv(w_priv),
		.l2_empty(w_l2_empty),
		.page_table_root(w_page_table_root),
		.l2_probe_val(w_l2_probe_val),
		.l2_probe_addr(w_l2_probe_addr),
		.l2_probe_ack(w_l2_probe_ack),
		.l1d_state(l1d_state),
		.restart_complete(w_restart_complete),
		.paging_active(w_paging_active),
		.clear_tlb(w_clear_tlb),
		.page_walk_req_va(w_l1d_page_walk_req_va),
		.page_walk_req_valid(w_l1d_page_walk_req_valid),
		.page_walk_rsp_gnt(w_mmu_gnt_l1d),
		.page_walk_rsp_valid(w_l1d_rsp_valid),
		.page_walk_rsp(page_walk_rsp),
		.head_of_rob_ptr_valid(head_of_rob_ptr_valid),
		.head_of_rob_ptr(w_head_of_rob_ptr),
		.retired_rob_ptr_valid(retired_rob_ptr_valid),
		.retired_rob_ptr_two_valid(retired_rob_ptr_two_valid),
		.retired_rob_ptr(retired_rob_ptr),
		.retired_rob_ptr_two(retired_rob_ptr_two),
		.memq_empty(memq_empty),
		.drain_ds_complete(drain_ds_complete),
		.dead_rob_mask(dead_rob_mask),
		.flush_req(flush_req_l1d),
		.flush_cl_req(flush_cl_req),
		.flush_cl_addr(flush_cl_addr),
		.flush_complete(l1d_flush_complete),
		.core_mem_va_req_valid(core_mem_req_valid),
		.core_mem_va_req(core_mem_req),
		.core_mem_va_req_ack(core_mem_req_ack),
		.core_store_data_valid(core_store_data_valid),
		.core_store_data(core_store_data),
		.core_store_data_ack(core_store_data_ack),
		.core_mem_rsp_valid(core_mem_rsp_valid),
		.core_mem_rsp(core_mem_rsp),
		.mem_rdy(w_l2_l1d_rdy),
		.mem_req_valid(l1d_mem_req_valid),
		.mem_req(l1d_mem_req),
		.l2_rsp_valid(l1d_mem_rsp_valid),
		.l2_rsp_load_data(w_l1_mem_load_data),
		.l2_rsp_tag(w_l1d_mem_rsp_tag),
		.l2_rsp_addr(w_l1d_mem_rsp_addr),
		.l2_rsp_writeback(w_l1d_mem_rsp_writeback),
		.mtimecmp(w_mtimecmp),
		.mtimecmp_val(w_mtimecmp_val),
		.cache_accesses(l1d_cache_accesses),
		.cache_hits(l1d_cache_hits),
		.tlb_hits(w_l1d_tlb_hits),
		.tlb_accesses(w_l1d_tlb_accesses)
	);
	wire [63:0] w_l1i_page_walk_req_va;
	wire w_l1i_page_walk_req_valid;
	wire r_l1i_page_walk_rsp_valid;
	wire r_l1i_page_walk_rsp_fault;
	wire [63:0] r_l1i_page_walk_rsp_pa;
	wire [63:0] t_l1i_pa;
	wire w_core_mark_dirty_valid;
	wire [63:0] w_core_mark_dirty_addr;
	wire w_core_mark_dirty_rsp_valid;
	mmu mmu0(
		.clk(clk),
		.reset(reset),
		.clear_tlb(w_clear_tlb),
		.page_table_root(w_page_table_root),
		.l1i_req(w_l1i_page_walk_req_valid),
		.l1i_va(w_l1i_page_walk_req_va),
		.l1d_req(w_l1d_page_walk_req_valid),
		.l1d_st(1'b0),
		.l1d_va(w_l1d_page_walk_req_va),
		.mem_req_valid(w_mmu_req_valid),
		.mem_req_addr(w_mmu_req_addr),
		.mem_req_data(w_mmu_req_data),
		.mem_req_store(w_mmu_req_store),
		.mem_rsp_valid(w_mmu_rsp_valid),
		.mem_rsp_data(w_mmu_rsp_data),
		.page_walk_rsp(page_walk_rsp),
		.l1d_rsp_valid(w_l1d_rsp_valid),
		.l1i_rsp_valid(w_l1i_rsp_valid),
		.l1i_gnt(w_mmu_gnt_l1i),
		.l1d_gnt(w_mmu_gnt_l1d),
		.core_mark_dirty_valid(w_core_mark_dirty_valid),
		.core_mark_dirty_addr(w_core_mark_dirty_addr),
		.core_mark_dirty_rsp_valid(w_core_mark_dirty_rsp_valid),
		.mem_mark_valid(w_mem_mark_valid),
		.mem_mark_accessed(w_mem_mark_accessed),
		.mem_mark_dirty(w_mem_mark_dirty),
		.mem_mark_addr(w_mem_mark_addr),
		.mem_mark_rsp_valid(w_mem_mark_rsp_valid),
		.mmu_state(mmu_state)
	);
	l1i_2way icache(
		.clk(clk),
		.reset(reset),
		.l1i_state(l1i_state),
		.mode64(w_mode64),
		.priv(w_priv),
		.page_table_root(w_page_table_root),
		.paging_active(w_paging_active),
		.clear_tlb(w_clear_tlb),
		.page_walk_req_va(w_l1i_page_walk_req_va),
		.page_walk_req_valid(w_l1i_page_walk_req_valid),
		.page_walk_rsp_valid(w_l1i_rsp_valid),
		.page_walk_rsp(page_walk_rsp),
		.flush_req(flush_req_l1i),
		.flush_complete(l1i_flush_complete),
		.restart_pc(restart_pc),
		.restart_src_pc(restart_src_pc),
		.restart_src_is_indirect(restart_src_is_indirect),
		.restart_valid(restart_valid),
		.restart_ack(restart_ack),
		.retire_reg_ptr(retire_reg_ptr),
		.retire_reg_data(retire_reg_data),
		.retire_reg_valid(retire_reg_valid),
		.branch_pc_valid(t_branch_pc_valid),
		.branch_pc_is_indirect(t_branch_pc_is_indirect),
		.branch_pc(t_branch_pc),
		.target_pc(t_target_pc),
		.took_branch(took_branch),
		.branch_fault(t_branch_fault),
		.branch_pht_idx(branch_pht_idx),
		.retire_valid(retire_valid),
		.retired_call(retired_call),
		.retired_ret(retired_ret),
		.insn(insn),
		.insn_valid(insn_valid),
		.insn_ack(insn_ack),
		.insn_two(insn2),
		.insn_valid_two(insn_valid2),
		.insn_ack_two(insn_ack2),
		.mem_req_valid(l1i_mem_req_valid),
		.mem_req_addr(l1i_mem_req_addr),
		.mem_req_opcode(l1i_mem_req_opcode),
		.mem_rsp_valid(l1i_mem_rsp_valid),
		.mem_rsp_load_data(w_l1_mem_load_data),
		.cache_accesses(l1i_cache_accesses),
		.cache_hits(l1i_cache_hits),
		.tlb_hits(w_l1i_tlb_hits),
		.tlb_accesses(w_l1i_tlb_accesses)
	);
	core cpu(
		.clk(clk),
		.reset(reset),
		.putchar_fifo_out(putchar_fifo_out),
		.putchar_fifo_empty(putchar_fifo_empty),
		.putchar_fifo_pop(putchar_fifo_pop),
		.putchar_fifo_wptr(putchar_fifo_wptr),
		.putchar_fifo_rptr(putchar_fifo_rptr),
		.restart_complete(w_restart_complete),
		.syscall_emu(syscall_emu),
		.core_state(core_state),
		.took_exc(took_exc),
		.priv(w_priv),
		.clear_tlb(w_clear_tlb),
		.paging_active(w_paging_active),
		.page_table_root(w_page_table_root),
		.mode64(w_mode64),
		.resume(resume),
		.memq_empty(memq_empty),
		.l2_empty(w_l2_empty),
		.drain_ds_complete(drain_ds_complete),
		.dead_rob_mask(dead_rob_mask),
		.head_of_rob_ptr_valid(head_of_rob_ptr_valid),
		.head_of_rob_ptr(w_head_of_rob_ptr),
		.resume_pc(resume_pc),
		.ready_for_resume(ready_for_resume),
		.flush_req_l1d(flush_req_l1d),
		.flush_req_l1i(flush_req_l1i),
		.flush_cl_req(flush_cl_req),
		.flush_cl_addr(flush_cl_addr),
		.l1d_flush_complete(l1d_flush_complete),
		.l1i_flush_complete(l1i_flush_complete),
		.l2_flush_complete(w_l2_flush_complete),
		.insn(insn),
		.insn_valid(insn_valid),
		.insn_ack(insn_ack),
		.insn_two(insn2),
		.insn_valid_two(insn_valid2),
		.insn_ack_two(insn_ack2),
		.branch_pc(t_branch_pc),
		.target_pc(t_target_pc),
		.branch_pc_valid(t_branch_pc_valid),
		.branch_pc_is_indirect(t_branch_pc_is_indirect),
		.branch_fault(t_branch_fault),
		.took_branch(took_branch),
		.branch_pht_idx(branch_pht_idx),
		.restart_pc(restart_pc),
		.restart_src_pc(restart_src_pc),
		.restart_src_is_indirect(restart_src_is_indirect),
		.restart_valid(restart_valid),
		.restart_ack(restart_ack),
		.core_mem_req_ack(core_mem_req_ack),
		.core_mem_req_valid(core_mem_req_valid),
		.core_mem_req(core_mem_req),
		.core_store_data_valid(core_store_data_valid),
		.core_store_data(core_store_data),
		.core_store_data_ack(core_store_data_ack),
		.core_mem_rsp_valid(core_mem_rsp_valid),
		.core_mem_rsp(core_mem_rsp),
		.alloc_valid(alloc_valid),
		.alloc_two_valid(alloc_two_valid),
		.iq_one_valid(iq_one_valid),
		.iq_none_valid(iq_none_valid),
		.in_branch_recovery(in_branch_recovery),
		.retire_reg_ptr(retire_reg_ptr),
		.retire_reg_data(retire_reg_data),
		.retire_reg_valid(retire_reg_valid),
		.retire_reg_two_ptr(retire_reg_two_ptr),
		.retire_reg_two_data(retire_reg_two_data),
		.retire_reg_two_valid(retire_reg_two_valid),
		.retire_valid(retire_valid),
		.retire_two_valid(retire_two_valid),
		.retire_pc(retire_pc),
		.retire_two_pc(retire_two_pc),
		.rob_empty(rob_empty),
		.retired_call(retired_call),
		.retired_ret(retired_ret),
		.retired_rob_ptr_valid(retired_rob_ptr_valid),
		.retired_rob_ptr_two_valid(retired_rob_ptr_two_valid),
		.retired_rob_ptr(retired_rob_ptr),
		.retired_rob_ptr_two(retired_rob_ptr_two),
		.monitor_ack(monitor_ack),
		.mtimecmp(w_mtimecmp),
		.mtimecmp_val(w_mtimecmp_val),
		.took_irq(took_irq),
		.got_break(got_break),
		.got_ud(got_ud),
		.got_bad_addr(),
		.got_monitor(got_monitor),
		.inflight(inflight),
		.epc(epc),
		.core_mark_dirty_valid(w_core_mark_dirty_valid),
		.core_mark_dirty_addr(w_core_mark_dirty_addr),
		.core_mark_dirty_rsp_valid(w_core_mark_dirty_rsp_valid),
		.counters(t_counters)
	);
	initial _sv2v_0 = 0;
endmodule
module core_l1d_l1i (
	clk,
	reset,
	syscall_emu,
	core_state,
	l1i_state,
	l1d_state,
	l2_state,
	memq_empty,
	putchar_fifo_out,
	putchar_fifo_empty,
	putchar_fifo_pop,
	putchar_fifo_wptr,
	putchar_fifo_rptr,
	took_exc,
	paging_active,
	page_table_root,
	extern_irq,
	in_flush_mode,
	resume,
	resume_pc,
	ready_for_resume,
	mem_req_valid,
	mem_req_addr,
	mem_req_store_data,
	mem_req_opcode,
	mem_rsp_valid,
	mem_req_gnt,
	mem_rsp_load_data,
	mem_req_tag,
	mem_rsp_tag,
	alloc_valid,
	alloc_two_valid,
	iq_one_valid,
	iq_none_valid,
	in_branch_recovery,
	retire_reg_ptr,
	retire_reg_data,
	retire_reg_valid,
	retire_reg_two_ptr,
	retire_reg_two_data,
	retire_reg_two_valid,
	retire_valid,
	retire_two_valid,
	rob_empty,
	retire_pc,
	retire_two_pc,
	branch_pc,
	branch_pc_valid,
	branch_fault,
	l1i_cache_accesses,
	l1i_cache_hits,
	l1d_cache_accesses,
	l1d_cache_hits,
	l2_cache_accesses,
	l2_cache_hits,
	monitor_ack,
	took_irq,
	got_break,
	got_ud,
	got_bad_addr,
	got_monitor,
	inflight,
	epc,
	restart_ack,
	priv
);
	localparam L1D_CL_LEN = 16;
	localparam L1D_CL_LEN_BITS = 128;
	input wire clk;
	input wire reset;
	input wire syscall_emu;
	output wire [4:0] core_state;
	output wire [3:0] l1i_state;
	output wire [3:0] l1d_state;
	output wire [4:0] l2_state;
	output wire memq_empty;
	output wire [7:0] putchar_fifo_out;
	output wire putchar_fifo_empty;
	input wire putchar_fifo_pop;
	input wire [3:0] putchar_fifo_wptr;
	input wire [3:0] putchar_fifo_rptr;
	output wire took_exc;
	output wire paging_active;
	output wire [63:0] page_table_root;
	input wire extern_irq;
	input wire resume;
	input wire [31:0] resume_pc;
	output wire in_flush_mode;
	output wire ready_for_resume;
	output wire [31:0] branch_pc;
	output wire branch_pc_valid;
	output wire branch_fault;
	output wire [63:0] l1i_cache_accesses;
	output wire [63:0] l1i_cache_hits;
	output wire [63:0] l1d_cache_accesses;
	output wire [63:0] l1d_cache_hits;
	output wire [63:0] l2_cache_accesses;
	output wire [63:0] l2_cache_hits;
	output wire mem_req_valid;
	output wire [31:0] mem_req_addr;
	output wire [127:0] mem_req_store_data;
	output wire [3:0] mem_req_opcode;
	input wire mem_req_gnt;
	input wire mem_rsp_valid;
	input wire [127:0] mem_rsp_load_data;
	output wire [1:0] mem_req_tag;
	input wire [1:0] mem_rsp_tag;
	output wire alloc_valid;
	output wire alloc_two_valid;
	output wire iq_one_valid;
	output wire iq_none_valid;
	output wire in_branch_recovery;
	output wire [4:0] retire_reg_ptr;
	output wire [31:0] retire_reg_data;
	output wire retire_reg_valid;
	output wire [4:0] retire_reg_two_ptr;
	output wire [31:0] retire_reg_two_data;
	output wire retire_reg_two_valid;
	output wire retire_valid;
	output wire retire_two_valid;
	output wire rob_empty;
	output wire [31:0] retire_pc;
	output wire [31:0] retire_two_pc;
	input wire monitor_ack;
	output wire took_irq;
	output wire got_break;
	output wire got_ud;
	output wire got_bad_addr;
	output wire got_monitor;
	output wire [5:0] inflight;
	output wire [31:0] epc;
	output wire restart_ack;
	output wire [1:0] priv;
	wire [63:0] w_resume_pc64 = {32'd0, resume_pc};
	wire [63:0] w_mem_req_addr64;
	assign mem_req_addr = w_mem_req_addr64[31:0];
	wire [63:0] w_retire_reg_data64;
	wire [63:0] w_retire_reg_two_data64;
	assign retire_reg_data = w_retire_reg_data64[31:0];
	assign retire_reg_two_data = w_retire_reg_two_data64[31:0];
	wire [63:0] w_retire_pc64;
	wire [63:0] w_retire_two_pc64;
	assign retire_pc = w_retire_pc64[31:0];
	assign retire_two_pc = w_retire_two_pc64[31:0];
	wire [63:0] w_branch_pc64;
	assign branch_pc = w_branch_pc64[31:0];
	wire [63:0] w_epc64;
	assign epc = w_epc64[31:0];
	core_l1d_l1i_64 c(
		.clk(clk),
		.reset(reset),
		.syscall_emu(syscall_emu),
		.core_state(core_state),
		.l1i_state(l1i_state),
		.l1d_state(l1d_state),
		.l2_state(l2_state),
		.memq_empty(memq_empty),
		.putchar_fifo_out(putchar_fifo_out),
		.putchar_fifo_empty(putchar_fifo_empty),
		.putchar_fifo_pop(putchar_fifo_pop),
		.putchar_fifo_wptr(putchar_fifo_wptr),
		.putchar_fifo_rptr(putchar_fifo_rptr),
		.took_exc(took_exc),
		.paging_active(paging_active),
		.page_table_root(page_table_root),
		.extern_irq(extern_irq),
		.in_flush_mode(in_flush_mode),
		.resume(resume),
		.resume_pc(w_resume_pc64),
		.ready_for_resume(ready_for_resume),
		.mem_req_valid(mem_req_valid),
		.mem_req_addr(w_mem_req_addr64),
		.mem_req_store_data(mem_req_store_data),
		.mem_req_opcode(mem_req_opcode),
		.mem_rsp_valid(mem_rsp_valid),
		.mem_req_gnt(mem_req_gnt),
		.mem_rsp_load_data(mem_rsp_load_data),
		.mem_rsp_tag(mem_rsp_tag),
		.mem_req_tag(mem_req_tag),
		.alloc_valid(alloc_valid),
		.alloc_two_valid(alloc_two_valid),
		.iq_one_valid(iq_one_valid),
		.iq_none_valid(iq_none_valid),
		.in_branch_recovery(in_branch_recovery),
		.retire_reg_ptr(retire_reg_ptr),
		.retire_reg_data(w_retire_reg_data64),
		.retire_reg_valid(retire_reg_valid),
		.retire_reg_two_ptr(retire_reg_two_ptr),
		.retire_reg_two_data(w_retire_reg_two_data64),
		.retire_reg_two_valid(retire_reg_two_valid),
		.retire_valid(retire_valid),
		.retire_two_valid(retire_two_valid),
		.rob_empty(rob_empty),
		.retire_pc(w_retire_pc64),
		.retire_two_pc(w_retire_two_pc64),
		.branch_pc(w_branch_pc64),
		.branch_pc_valid(branch_pc_valid),
		.branch_fault(branch_fault),
		.l1i_cache_accesses(l1i_cache_accesses),
		.l1i_cache_hits(l1i_cache_hits),
		.l1d_cache_accesses(l1d_cache_accesses),
		.l1d_cache_hits(l1d_cache_hits),
		.l2_cache_accesses(l2_cache_accesses),
		.l2_cache_hits(l2_cache_hits),
		.l1i_tlb_accesses(),
		.l1i_tlb_hits(),
		.l1d_tlb_accesses(),
		.l1d_tlb_hits(),
		.monitor_ack(monitor_ack),
		.took_irq(took_irq),
		.got_break(got_break),
		.got_ud(got_ud),
		.got_bad_addr(got_bad_addr),
		.got_monitor(got_monitor),
		.inflight(inflight),
		.epc(w_epc64),
		.restart_ack(restart_ack),
		.priv(priv)
	);
endmodule

module shift_right (
	y,
	is_left,
	is_signed,
	data,
	distance
);
	parameter LG_W = 5;
	localparam W = 1 << LG_W;
	input wire is_left;
	input wire is_signed;
	input wire [W - 1:0] data;
	input wire [LG_W - 1:0] distance;
	output wire [W - 1:0] y;
	wire w_sb = (is_signed ? data[W - 1] : 1'b0);
	wire [(2 * W) - 1:0] w_data = (is_left ? {data, {W {1'b0}}} : {{W {w_sb}}, data});
	wire [LG_W:0] w_inv_dist = W - {1'b0, distance};
	wire [LG_W:0] w_distance = (is_left ? w_inv_dist[LG_W:0] : {1'b0, distance});
	wire [(2 * W) - 1:0] w_shift = w_data >> w_distance;
	assign y = w_shift[W - 1:0];
endmodule

module reg_ram1rw (
	clk,
	addr,
	wr_data,
	wr_en,
	rd_data
);
	input wire clk;
	parameter WIDTH = 1;
	parameter LG_DEPTH = 1;
	input wire [LG_DEPTH - 1:0] addr;
	input wire [WIDTH - 1:0] wr_data;
	input wire wr_en;
	output reg [WIDTH - 1:0] rd_data;
	localparam DEPTH = 1 << LG_DEPTH;
	reg [WIDTH - 1:0] r_ram [DEPTH - 1:0];
	always @(posedge clk) begin
		rd_data <= r_ram[addr];
		if (wr_en)
			r_ram[addr] <= wr_data;
	end
endmodule

module predecode (
	insn,
	pd
);
	reg _sv2v_0;
	input wire [31:0] insn;
	output reg [2:0] pd;
	reg [6:0] opcode;
	reg [4:0] rd;
	reg [4:0] rs1;
	reg rd_is_link;
	reg rs1_is_link;
	always @(*) begin
		if (_sv2v_0)
			;
		pd = 'd0;
		opcode = insn[6:0];
		rd = insn[11:7];
		rs1 = insn[19:15];
		rd_is_link = (rd == 'd1) || (rd == 'd5);
		rs1_is_link = (rs1 == 'd1) || (rs1 == 'd5);
		case (opcode)
			7'h63: pd = 'd1;
			7'h67:
				if (rd == 'd0)
					pd = (rs1_is_link ? 'd2 : 'd4);
				else
					pd = 'd6;
			7'h6f:
				if (rd_is_link)
					pd = 'd5;
				else
					pd = 'd3;
			default:
				;
		endcase
	end
	initial _sv2v_0 = 0;
endmodule

module decode_riscv (
	mode64,
	priv,
	insn,
	page_fault,
	irq,
	pc,
	insn_pred,
	pht_idx,
	insn_pred_target,
	syscall_emu,
	uop
);
	reg _sv2v_0;
	input wire mode64;
	input wire [1:0] priv;
	input wire [31:0] insn;
	input wire page_fault;
	input wire irq;
	input wire [63:0] pc;
	input wire insn_pred;
	input wire [15:0] pht_idx;
	input wire [63:0] insn_pred_target;
	input wire syscall_emu;
	output reg [251:0] uop;
	wire [6:0] opcode = (page_fault | irq ? 'd0 : insn[6:0]);
	localparam ZP = 2;
	wire [6:0] rd = {{ZP {1'b0}}, insn[11:7]};
	wire [6:0] rs1 = {{ZP {1'b0}}, insn[19:15]};
	wire [6:0] rs2 = {{ZP {1'b0}}, insn[24:20]};
	reg rd_is_link;
	reg rs1_is_link;
	wire [6:0] rt = {{ZP {1'b0}}, insn[20:16]};
	wire [6:0] shamt = {{ZP {1'b0}}, insn[10:6]};
	reg [63:0] t_imm;
	localparam PP = 32;
	reg [5:0] csr_id;
	wire [63:0] w_pc_imm;
	wire [63:0] w_pc_imm_;
	always @(*) begin
		if (_sv2v_0)
			;
		t_imm = 'd0;
		case (opcode)
			7'h17: t_imm = {{PP {insn[31]}}, insn[31:12], 12'd0};
			7'h63: t_imm = {{51 {insn[31]}}, insn[31], insn[7], insn[30:25], insn[11:8], 1'b0};
			7'h6f: t_imm = {{43 {insn[31]}}, insn[31], insn[19:12], insn[20], insn[30:21], 1'b0};
			default:
				;
		endcase
	end
	mwidth_add imm_add(
		.A(pc),
		.B(t_imm),
		.Y(w_pc_imm_)
	);
	assign w_pc_imm = (mode64 ? w_pc_imm_ : {{32 {w_pc_imm_[31]}}, w_pc_imm_[31:0]});
	function [5:0] decode_csr;
		input reg [11:0] csr;
		input reg [1:0] priv;
		reg [5:0] x;
		begin
			case (csr)
				12'h100: x = (priv == 2'd0 ? 6'd45 : 6'd0);
				12'h104: x = (priv == 2'd0 ? 6'd45 : 6'd1);
				12'h105: x = (priv == 2'd0 ? 6'd45 : 6'd2);
				12'h106: x = (priv == 2'd0 ? 6'd45 : 6'd6);
				12'h140: x = (priv == 2'd0 ? 6'd45 : 6'd3);
				12'h141: x = (priv == 2'd0 ? 6'd45 : 6'd4);
				12'h142: x = (priv == 2'd0 ? 6'd45 : 6'd5);
				12'h143: x = (priv == 2'd0 ? 6'd45 : 6'd7);
				12'h144: x = (priv == 2'd0 ? 6'd45 : 6'd8);
				12'h180: x = (priv == 2'd0 ? 6'd45 : 6'd9);
				12'h300: x = (priv != 2'd3 ? 6'd45 : 6'd10);
				12'h301: x = (priv != 2'd3 ? 6'd45 : 6'd14);
				12'h302: x = (priv != 2'd3 ? 6'd45 : 6'd15);
				12'h303: x = (priv != 2'd3 ? 6'd45 : 6'd16);
				12'h304: x = (priv != 2'd3 ? 6'd45 : 6'd11);
				12'h305: x = (priv != 2'd3 ? 6'd45 : 6'd17);
				12'h306: x = (priv != 2'd3 ? 6'd45 : 6'd13);
				12'h340: x = (priv != 2'd3 ? 6'd45 : 6'd20);
				12'h341: x = (priv != 2'd3 ? 6'd45 : 6'd18);
				12'h342: x = (priv != 2'd3 ? 6'd45 : 6'd12);
				12'h343: x = (priv != 2'd3 ? 6'd45 : 6'd17);
				12'h344: x = (priv != 2'd3 ? 6'd45 : 6'd19);
				12'h3a0: x = 6'd25;
				12'h3b0: x = 6'd21;
				12'h3b1: x = 6'd22;
				12'h3b2: x = 6'd23;
				12'h3b3: x = 6'd24;
				12'hc00: x = 6'd26;
				12'hc01: x = 6'd27;
				12'hc02: x = 6'd28;
				12'hc03: x = 6'd29;
				12'hc04: x = 6'd30;
				12'hc05: x = 6'd31;
				12'hc06: x = 6'd32;
				12'hc07: x = 6'd33;
				12'hc08: x = 6'd34;
				12'hc09: x = 6'd35;
				12'hc0a: x = 6'd36;
				12'hc0b: x = 6'd37;
				12'hc0c: x = 6'd38;
				12'hc0d: x = 6'd39;
				12'hc0e: x = 6'd40;
				12'hf11: x = (priv != 2'd3 ? 6'd45 : 6'd41);
				12'hf12: x = (priv != 2'd3 ? 6'd45 : 6'd42);
				12'hf13: x = (priv != 2'd3 ? 6'd45 : 6'd43);
				12'hf14: x = (priv != 2'd3 ? 6'd45 : 6'd44);
				default: x = 6'd45;
			endcase
			decode_csr = x;
		end
	endfunction
	always @(*) begin
		if (_sv2v_0)
			;
		csr_id = decode_csr(insn[31:20], priv);
		rd_is_link = (rd == 'd1) || (rd == 'd5);
		rs1_is_link = (rs1 == 'd1) || (rs1 == 'd5);
		uop[251-:7] = (page_fault ? 7'd94 : (irq ? 7'd95 : 7'd96));
		uop[244-:7] = 'd0;
		uop[236-:7] = 'd0;
		uop[228-:7] = 'd0;
		uop[237] = 1'b0;
		uop[229] = 1'b0;
		uop[221] = 1'b0;
		uop[156-:16] = 16'd0;
		uop[140-:48] = {48 {1'b0}};
		uop[220-:64] = 'd0;
		uop[92-:64] = pc;
		uop[23] = 1'b0;
		uop[22] = 1'b0;
		uop[28-:5] = 'd0;
		uop[21] = 1'b0;
		uop[19] = 1'b0;
		uop[16-:16] = pht_idx;
		uop[18] = 1'b0;
		uop[20] = 1'b0;
		uop[0] = 1'b0;
		uop[17] = 1'b0;
		case (opcode)
			7'h03: begin
				uop[228-:7] = rd;
				uop[244-:7] = rs1;
				uop[221] = rd != 'd0;
				uop[237] = 1'b1;
				uop[18] = 1'b1;
				uop[220-:64] = {{52 {insn[31]}}, insn[31:20]};
				case (insn[14:12])
					3'd0: uop[251-:7] = 7'd51;
					3'd1: uop[251-:7] = 7'd52;
					3'd2: uop[251-:7] = 7'd53;
					3'd3: uop[251-:7] = 7'd55;
					3'd4: uop[251-:7] = 7'd56;
					3'd5: uop[251-:7] = 7'd57;
					3'd6: uop[251-:7] = 7'd54;
					default:
						;
				endcase
			end
			7'h0f:
				case (insn[14:12])
					3'd1: begin
						uop[20] = 1'b1;
						uop[251-:7] = 7'd93;
						uop[23] = 1'b1;
						uop[22] = 1'b1;
					end
					default: uop[251-:7] = 7'd73;
				endcase
			7'h13: begin
				uop[228-:7] = rd;
				uop[244-:7] = rs1;
				uop[221] = rd != 'd0;
				uop[237] = rd != 'd0;
				uop[20] = 1'b1;
				uop[220-:64] = {{52 {insn[31]}}, insn[31:20]};
				case (insn[14:12])
					3'd0: begin
						uop[251-:7] = (rd == 'd0 ? 7'd73 : 7'd70);
						uop[0] = 1'b1;
					end
					3'd1: begin
						uop[251-:7] = (rd == 'd0 ? 7'd73 : 7'd48);
						uop[0] = 1'b1;
					end
					3'd2: begin
						uop[251-:7] = (rd == 'd0 ? 7'd73 : 7'd36);
						uop[0] = 1'b1;
					end
					3'd3: begin
						uop[251-:7] = (rd == 'd0 ? 7'd73 : 7'd37);
						uop[0] = 1'b1;
					end
					3'd4: begin
						uop[251-:7] = (rd == 'd0 ? 7'd73 : 7'd63);
						uop[0] = 1'b1;
					end
					3'd5:
						case (insn[31:26])
							6'h00: begin
								uop[251-:7] = (rd == 'd0 ? 7'd73 : 7'd50);
								uop[0] = 1'b1;
							end
							6'h10: begin
								uop[251-:7] = (rd == 'd0 ? 7'd73 : 7'd49);
								uop[0] = 1'b1;
							end
							default:
								;
						endcase
					3'd6: begin
						uop[251-:7] = (rd == 'd0 ? 7'd73 : 7'd62);
						uop[0] = 1'b1;
					end
					3'd7: begin
						uop[251-:7] = (rd == 'd0 ? 7'd73 : 7'd40);
						uop[0] = 1'b1;
					end
				endcase
			end
			7'h17: begin
				uop[251-:7] = (rd == 'd0 ? 7'd73 : 7'd71);
				uop[228-:7] = rd;
				uop[221] = rd != 'd0;
				uop[20] = 1'b1;
				uop[0] = 1'b1;
				uop[220-:64] = w_pc_imm;
			end
			7'h1b:
				if (mode64) begin
					uop[228-:7] = rd;
					uop[244-:7] = rs1;
					uop[221] = rd != 'd0;
					uop[237] = rd != 'd0;
					uop[20] = 1'b1;
					uop[220-:64] = {{52 {insn[31]}}, insn[31:20]};
					case (insn[14:12])
						3'd0: begin
							uop[251-:7] = (rd == 'd0 ? 7'd73 : 7'd79);
							uop[0] = 1'b1;
						end
						3'd1: begin
							uop[251-:7] = (rd == 'd0 ? 7'd73 : 7'd80);
							uop[0] = 1'b1;
						end
						3'd5: begin
							uop[251-:7] = (rd == 'd0 ? 7'd73 : (insn[31:26] == 'd0 ? 7'd81 : 7'd82));
							uop[0] = 1'b1;
						end
						default:
							;
					endcase
				end
			7'h23: begin
				uop[244-:7] = rs1;
				uop[236-:7] = rs2;
				uop[237] = 1'b1;
				uop[229] = 1'b1;
				uop[18] = 1'b1;
				uop[17] = 1'b1;
				uop[220-:64] = {{52 {insn[31]}}, insn[31:25], insn[11:7]};
				case (insn[14:12])
					3'd0: uop[251-:7] = 7'd58;
					3'd1: uop[251-:7] = 7'd59;
					3'd2: uop[251-:7] = 7'd60;
					3'd3: uop[251-:7] = 7'd61;
					default:
						;
				endcase
			end
			7'h2f:
				if ((insn[14:12] == 3'd2) || (insn[14:12] == 3'd3)) begin
					uop[244-:7] = rs1;
					uop[236-:7] = rs2;
					uop[228-:7] = rd;
					uop[221] = rd != 'd0;
					uop[237] = 1'b1;
					uop[18] = 1'b1;
					uop[140-:48] = {43'd0, insn[31:27]};
					uop[23] = 1'b1;
					case (insn[31:27])
						5'd0: begin
							uop[251-:7] = (insn[14:12] == 3'd2 ? 7'd11 : 7'd12);
							uop[229] = 1'b1;
						end
						5'd1: begin
							uop[251-:7] = (insn[14:12] == 3'd2 ? 7'd11 : 7'd12);
							uop[229] = 1'b1;
						end
						5'd2: uop[251-:7] = (insn[14:12] == 3'd2 ? 7'd7 : 7'd8);
						5'd3: begin
							uop[251-:7] = (insn[14:12] == 3'd2 ? 7'd9 : 7'd10);
							uop[229] = 1'b1;
						end
						5'd4: begin
							uop[251-:7] = (insn[14:12] == 3'd2 ? 7'd9 : 7'd10);
							uop[229] = 1'b1;
						end
						5'd8: begin
							uop[251-:7] = (insn[14:12] == 3'd2 ? 7'd11 : 7'd12);
							uop[229] = 1'b1;
						end
						5'd12: begin
							uop[251-:7] = (insn[14:12] == 3'd2 ? 7'd11 : 7'd12);
							uop[229] = 1'b1;
						end
						5'd28: begin
							uop[251-:7] = (insn[14:12] == 3'd2 ? 7'd11 : 7'd12);
							uop[229] = 1'b1;
						end
						default:
							;
					endcase
				end
			7'h33: begin
				uop[228-:7] = rd;
				uop[221] = rd != 'd0;
				uop[237] = 1'b1;
				uop[244-:7] = rs1;
				uop[229] = 1'b1;
				uop[236-:7] = rs2;
				uop[20] = 1'b1;
				case (insn[14:12])
					3'd0:
						case (insn[31:25])
							7'h00: begin
								uop[251-:7] = (rd != 'd0 ? 7'd38 : 7'd73);
								uop[0] = 1'b1;
							end
							7'h01: uop[251-:7] = (rd != 'd0 ? 7'd29 : 7'd73);
							7'h20: begin
								uop[251-:7] = (rd != 'd0 ? 7'd39 : 7'd73);
								uop[0] = 1'b1;
							end
							default:
								;
						endcase
					3'd1:
						case (insn[31:25])
							7'd0: begin
								uop[251-:7] = (rd != 'd0 ? 7'd47 : 7'd73);
								uop[0] = 1'b1;
							end
							7'h01: uop[251-:7] = (rd != 'd0 ? 7'd30 : 7'd73);
							default:
								;
						endcase
					3'd2:
						case (insn[31:25])
							7'd0: begin
								uop[251-:7] = (rd != 'd0 ? 7'd4 : 7'd73);
								uop[0] = 1'b1;
							end
							default:
								;
						endcase
					3'd3:
						case (insn[31:25])
							7'h00: begin
								uop[251-:7] = (rd != 'd0 ? 7'd5 : 7'd73);
								uop[0] = 1'b1;
							end
							7'h01: uop[251-:7] = (rd != 'd0 ? 7'd31 : 7'd73);
							default:
								;
						endcase
					3'd4:
						case (insn[31:25])
							7'h00: begin
								uop[251-:7] = (rd != 'd0 ? 7'd76 : 7'd73);
								uop[0] = 1'b1;
							end
							7'h01: uop[251-:7] = (rd != 'd0 ? 7'd32 : 7'd73);
							default:
								;
						endcase
					3'd5:
						case (insn[31:25])
							7'h00: begin
								uop[251-:7] = (rd != 'd0 ? 7'd0 : 7'd73);
								uop[0] = 1'b1;
							end
							7'h01: uop[251-:7] = (rd != 'd0 ? 7'd33 : 7'd73);
							7'h07: uop[251-:7] = (rd != 'd0 ? 7'd91 : 7'd73);
							7'h20: begin
								uop[251-:7] = (rd != 'd0 ? 7'd1 : 7'd73);
								uop[0] = 1'b1;
							end
							default:
								;
						endcase
					3'd6:
						case (insn[31:25])
							7'h00: begin
								uop[251-:7] = (rd != 'd0 ? 7'd75 : 7'd73);
								uop[0] = 1'b1;
							end
							7'h01: uop[251-:7] = (rd != 'd0 ? 7'd34 : 7'd73);
							default:
								;
						endcase
					3'd7:
						case (insn[31:25])
							7'h00: begin
								uop[251-:7] = (rd != 'd0 ? 7'd74 : 7'd73);
								uop[0] = 1'b1;
							end
							7'h01: uop[251-:7] = (rd != 'd0 ? 7'd35 : 7'd73);
							7'h07: uop[251-:7] = (rd != 'd0 ? 7'd92 : 7'd73);
							default:
								;
						endcase
					default:
						;
				endcase
			end
			7'h37: begin
				uop[251-:7] = (rd == 'd0 ? 7'd73 : 7'd72);
				uop[228-:7] = rd;
				uop[221] = rd != 'd0;
				uop[20] = 1'b1;
				uop[0] = 1'b1;
				uop[220-:64] = {{PP {insn[31]}}, insn[31:12], 12'd0};
			end
			7'h3b:
				if (mode64) begin
					uop[228-:7] = rd;
					uop[221] = rd != 'd0;
					uop[237] = 1'b1;
					uop[244-:7] = rs1;
					uop[229] = 1'b1;
					uop[236-:7] = rs2;
					uop[20] = 1'b1;
					if ((insn[14:12] == 'd0) && (insn[31:25] == 'd0)) begin
						uop[251-:7] = (rd != 'd0 ? 7'd77 : 7'd73);
						uop[0] = 1'b1;
					end
					else if ((insn[14:12] == 'd0) && (insn[31:25] == 'd32)) begin
						uop[251-:7] = (rd != 'd0 ? 7'd78 : 7'd73);
						uop[0] = 1'b1;
					end
					else if ((insn[14:12] == 'd0) && (insn[31:25] == 'd1))
						uop[251-:7] = (rd != 'd0 ? 7'd84 : 7'd73);
					else if ((insn[14:12] == 'd1) && (insn[31:25] == 'd0)) begin
						uop[251-:7] = (rd != 'd0 ? 7'd89 : 7'd73);
						uop[0] = 1'b1;
					end
					else if ((insn[14:12] == 'd4) && (insn[31:25] == 'd1))
						uop[251-:7] = (rd != 'd0 ? 7'd85 : 7'd73);
					else if ((insn[14:12] == 'd5) && (insn[31:25] == 'd0)) begin
						uop[251-:7] = (rd != 'd0 ? 7'd90 : 7'd73);
						uop[0] = 1'b1;
					end
					else if ((insn[14:12] == 'd5) && (insn[31:25] == 'd1))
						uop[251-:7] = (rd != 'd0 ? 7'd86 : 7'd73);
					else if ((insn[14:12] == 'd5) && (insn[31:25] == 'd32)) begin
						uop[251-:7] = (rd != 'd0 ? 7'd83 : 7'd73);
						uop[0] = 1'b1;
					end
					else if ((insn[14:12] == 'd6) && (insn[31:25] == 'd1))
						uop[251-:7] = (rd != 'd0 ? 7'd87 : 7'd73);
					else if ((insn[14:12] == 'd7) && (insn[31:25] == 'd1))
						uop[251-:7] = (rd != 'd0 ? 7'd88 : 7'd73);
				end
			7'h63: begin
				uop[244-:7] = rs1;
				uop[236-:7] = rs2;
				uop[237] = 1'b1;
				uop[229] = 1'b1;
				uop[20] = 1'b1;
				uop[220-:64] = w_pc_imm;
				uop[21] = insn_pred;
				uop[19] = 1'b1;
				uop[0] = 1'b1;
				case (insn[14:12])
					3'd0: uop[251-:7] = 7'd41;
					3'd1: uop[251-:7] = 7'd46;
					3'd4: uop[251-:7] = 7'd44;
					3'd5: uop[251-:7] = 7'd42;
					3'd6: uop[251-:7] = 7'd45;
					3'd7: uop[251-:7] = 7'd43;
					default:
						;
				endcase
			end
			7'h67: begin
				uop[237] = 1'b1;
				uop[244-:7] = rs1;
				uop[20] = 1'b1;
				uop[19] = 1'b1;
				uop[156-:16] = insn_pred_target[15:0];
				uop[140-:48] = insn_pred_target[63:16];
				uop[220-:64] = {{52 {insn[31]}}, insn[31:20]};
				uop[21] = 1'b1;
				uop[19] = 1'b1;
				uop[0] = 1'b1;
				if (rd == 'd0)
					uop[251-:7] = (rs1_is_link ? 7'd67 : 7'd66);
				else begin
					uop[251-:7] = 7'd68;
					uop[221] = 1'b1;
					uop[228-:7] = rd;
				end
			end
			7'h6f: begin
				uop[220-:64] = w_pc_imm;
				uop[19] = 1'b1;
				if (rd == 'd0) begin
					uop[251-:7] = 7'd64;
					uop[21] = 1'b1;
					uop[19] = 1'b1;
					uop[20] = 1'b1;
				end
				else begin
					uop[251-:7] = 7'd65;
					uop[221] = 1'b1;
					uop[228-:7] = rd;
					uop[21] = 1'b1;
					uop[19] = 1'b1;
					uop[20] = 1'b1;
					uop[0] = 1'b1;
				end
			end
			7'h73: begin
				uop[20] = 1'b1;
				if (insn[31:7] == 'd0) begin
					uop[251-:7] = (syscall_emu ? 7'd69 : 7'd18);
					uop[23] = 1'b1;
					uop[22] = syscall_emu == 1'b0;
				end
				else if ((insn[31:20] == 'd1) && (insn[19:7] == 'd0)) begin
					uop[251-:7] = (syscall_emu ? 7'd13 : 7'd19);
					uop[23] = 1'b1;
					uop[22] = 1'b1;
				end
				else if ((insn[31:25] == 'd9) && (rd == 'd0)) begin
					uop[251-:7] = 7'd28;
					uop[23] = 1'b1;
					uop[22] = 1'b1;
				end
				else if ((insn[31:20] == 12'h002) && (insn[19:7] == 'd0))
					uop[251-:7] = 7'd96;
				else if ((insn[31:20] == 12'h102) && (insn[19:7] == 'd0)) begin
					if (priv != 2'd0) begin
						uop[251-:7] = 7'd21;
						uop[23] = 1'b1;
						uop[22] = 1'b1;
						uop[156-:16] = 16'h000a;
					end
				end
				else if ((insn[31:20] == 12'h105) && (insn[19:7] == 'd0))
					uop[251-:7] = 7'd73;
				else if ((insn[31:20] == 12'h202) && (insn[19:7] == 'd0))
					uop[251-:7] = 7'd96;
				else if ((insn[31:20] == 12'h302) && (insn[19:7] == 'd0)) begin
					if (priv == 2'd3) begin
						uop[251-:7] = 7'd20;
						uop[23] = 1'b1;
						uop[22] = 1'b1;
						uop[156-:16] = 16'h000a;
					end
				end
				else begin
					uop[156-:16] = {5'd0, rs1[4:0], csr_id};
					if (csr_id != 6'd45)
						case (insn[14:12])
							3'd1: begin
								uop[251-:7] = 7'd22;
								uop[228-:7] = rd;
								uop[221] = rd != 'd0;
								uop[23] = 1'b1;
								uop[22] = 1'b1;
								uop[244-:7] = rs1;
								uop[237] = 1'b1;
							end
							3'd2:
								if (rs1 == 'd0) begin
									if ((((csr_id == 6'd44) | (csr_id == 6'd41)) | (csr_id == 6'd42)) | (csr_id == 6'd43)) begin
										uop[251-:7] = (rd == 'd0 ? 7'd73 : 7'd38);
										uop[228-:7] = rd;
										uop[221] = rd != 'd0;
										uop[244-:7] = 'd0;
										uop[237] = 1'b1;
										uop[236-:7] = 'd0;
										uop[229] = 1'b1;
										uop[0] = 1'b1;
									end
									else if (csr_id == 6'd26) begin
										uop[251-:7] = (rd == 'd0 ? 7'd73 : 7'd14);
										uop[228-:7] = rd;
										uop[221] = rd != 'd0;
										uop[23] = 1'b1;
									end
									else if (csr_id == 6'd28) begin
										uop[251-:7] = (rd == 'd0 ? 7'd73 : 7'd15);
										uop[228-:7] = rd;
										uop[221] = rd != 'd0;
										uop[23] = 1'b1;
									end
									else if (csr_id == 6'd30) begin
										uop[251-:7] = (rd == 'd0 ? 7'd73 : 7'd17);
										uop[228-:7] = rd;
										uop[221] = rd != 'd0;
										uop[23] = 1'b1;
									end
									else begin
										uop[251-:7] = 7'd23;
										uop[228-:7] = rd;
										uop[221] = rd != 'd0;
										uop[23] = 1'b1;
										uop[22] = 1'b1;
									end
								end
								else begin
									uop[251-:7] = 7'd23;
									uop[228-:7] = rd;
									uop[221] = rd != 'd0;
									uop[23] = 1'b1;
									uop[22] = 1'b1;
									uop[244-:7] = rs1;
									uop[237] = 1'b1;
								end
							3'd3: begin
								uop[251-:7] = 7'd24;
								uop[228-:7] = rd;
								uop[221] = rd != 'd0;
								uop[23] = 1'b1;
								uop[22] = 1'b1;
								uop[244-:7] = rs1;
								uop[237] = 1'b1;
							end
							3'd5: begin
								uop[251-:7] = 7'd25;
								uop[228-:7] = rd;
								uop[221] = rd != 'd0;
								uop[23] = 1'b1;
								uop[22] = 1'b1;
							end
							3'd6: begin
								uop[251-:7] = 7'd26;
								uop[228-:7] = rd;
								uop[221] = rd != 'd0;
								uop[23] = 1'b1;
								uop[22] = 1'b1;
							end
							3'd7: begin
								uop[251-:7] = 7'd27;
								uop[228-:7] = rd;
								uop[221] = rd != 'd0;
								uop[23] = 1'b1;
								uop[22] = 1'b1;
							end
							default:
								;
						endcase
				end
			end
			default:
				;
		endcase
	end
	initial _sv2v_0 = 0;
endmodule

module mwidth_add (
	A,
	B,
	Y
);
	input [63:0] A;
	input [63:0] B;
	output wire [63:0] Y;
	assign Y = A + B;
endmodule

module l1i_2way (
	clk,
	reset,
	l1i_state,
	priv,
	page_table_root,
	paging_active,
	clear_tlb,
	mode64,
	page_walk_req_va,
	page_walk_req_valid,
	page_walk_rsp_valid,
	page_walk_rsp,
	flush_req,
	flush_complete,
	restart_pc,
	restart_src_pc,
	restart_src_is_indirect,
	restart_valid,
	restart_ack,
	retire_valid,
	retired_call,
	retired_ret,
	retire_reg_ptr,
	retire_reg_data,
	retire_reg_valid,
	branch_pc_valid,
	branch_pc_is_indirect,
	branch_pc,
	target_pc,
	took_branch,
	branch_fault,
	branch_pht_idx,
	insn,
	insn_valid,
	insn_ack,
	insn_two,
	insn_valid_two,
	insn_ack_two,
	mem_req_valid,
	mem_req_addr,
	mem_req_opcode,
	mem_rsp_valid,
	mem_rsp_load_data,
	cache_accesses,
	cache_hits,
	tlb_accesses,
	tlb_hits
);
	reg _sv2v_0;
	input wire clk;
	input wire reset;
	output wire [3:0] l1i_state;
	input wire paging_active;
	input wire clear_tlb;
	input wire [1:0] priv;
	input wire [63:0] page_table_root;
	input wire mode64;
	output wire [63:0] page_walk_req_va;
	output wire page_walk_req_valid;
	input wire page_walk_rsp_valid;
	input wire [71:0] page_walk_rsp;
	input wire flush_req;
	output wire flush_complete;
	input wire [63:0] restart_pc;
	input wire [63:0] restart_src_pc;
	input wire restart_src_is_indirect;
	input wire restart_valid;
	output wire restart_ack;
	input wire retire_valid;
	input wire retired_call;
	input wire retired_ret;
	input wire [4:0] retire_reg_ptr;
	input wire [63:0] retire_reg_data;
	input wire retire_reg_valid;
	input wire branch_pc_valid;
	input wire branch_pc_is_indirect;
	input wire [63:0] branch_pc;
	input wire [63:0] target_pc;
	input wire took_branch;
	input wire branch_fault;
	input wire [15:0] branch_pht_idx;
	output reg [177:0] insn;
	output wire insn_valid;
	input wire insn_ack;
	output reg [177:0] insn_two;
	output wire insn_valid_two;
	input wire insn_ack_two;
	output wire mem_req_valid;
	localparam L1I_NUM_SETS = 256;
	localparam L1I_CL_LEN = 16;
	localparam L1I_CL_LEN_BITS = 128;
	localparam LG_WORDS_PER_CL = 2;
	localparam WORDS_PER_CL = 4;
	localparam N_TAG_BITS = 20;
	localparam IDX_START = 4;
	localparam IDX_STOP = 12;
	localparam WORD_START = 2;
	localparam WORD_STOP = 4;
	localparam N_FQ_ENTRIES = 8;
	localparam RETURN_STACK_ENTRIES = 8;
	localparam PHT_ENTRIES = 65536;
	localparam BTB_ENTRIES = 128;
	output wire [31:0] mem_req_addr;
	output wire [3:0] mem_req_opcode;
	input wire mem_rsp_valid;
	input wire [127:0] mem_rsp_load_data;
	output wire [63:0] cache_accesses;
	output wire [63:0] cache_hits;
	output wire [63:0] tlb_accesses;
	output wire [63:0] tlb_hits;
	reg [19:0] t_cache_tag;
	reg [19:0] r_cache_tag;
	wire w_last_out;
	wire [19:0] w_tag_out0;
	wire [19:0] w_tag_out1;
	reg r_pht_update;
	reg [1:0] r_pht_out;
	reg [1:0] t_pht_out;
	reg [1:0] t_pht_val;
	wire [7:0] r_pht_out_vec;
	wire [7:0] r_pht_update_out;
	reg [7:0] t_pht_val_vec;
	reg t_do_pht_wr;
	wire [15:0] n_pht_idx;
	reg [15:0] r_pht_idx;
	reg [15:0] r_pht_update_idx;
	reg r_take_br;
	reg [63:0] r_btb [127:0];
	wire [11:0] w_jump_out0;
	wire [11:0] w_jump_out1;
	reg [7:0] t_cache_idx;
	reg [7:0] r_cache_idx;
	reg r_mem_req_valid;
	reg n_mem_req_valid;
	reg [63:0] r_mem_req_addr;
	reg [63:0] n_mem_req_addr;
	wire [127:0] w_array_out0;
	wire [127:0] w_array_out1;
	reg [177:0] r_fq [7:0];
	reg [3:0] r_fq_head_ptr;
	reg [3:0] n_fq_head_ptr;
	reg [3:0] r_fq_next_head_ptr;
	reg [3:0] n_fq_next_head_ptr;
	reg [3:0] r_fq_next_tail_ptr;
	reg [3:0] n_fq_next_tail_ptr;
	reg [3:0] r_fq_next3_tail_ptr;
	reg [3:0] n_fq_next3_tail_ptr;
	reg [3:0] r_fq_next4_tail_ptr;
	reg [3:0] n_fq_next4_tail_ptr;
	reg [3:0] r_fq_tail_ptr;
	reg [3:0] n_fq_tail_ptr;
	reg r_resteer_bubble;
	reg n_resteer_bubble;
	reg fq_full;
	reg fq_next_empty;
	reg fq_empty;
	reg fq_full2;
	reg fq_full3;
	reg fq_full4;
	reg [511:0] r_spec_return_stack;
	reg [511:0] r_arch_return_stack;
	reg [2:0] n_arch_rs_tos;
	reg [2:0] r_arch_rs_tos;
	reg [2:0] n_spec_rs_tos;
	reg [2:0] r_spec_rs_tos;
	reg [2:0] t_next_spec_rs_tos;
	reg [15:0] n_arch_gbl_hist;
	reg [15:0] r_arch_gbl_hist;
	reg [15:0] n_spec_gbl_hist;
	reg [15:0] r_spec_gbl_hist;
	reg [15:0] r_last_spec_gbl_hist;
	reg [1:0] t_insn_idx;
	reg [1:0] t_branch_idx;
	reg [63:0] n_cache_accesses;
	reg [63:0] r_cache_accesses;
	reg [63:0] n_cache_hits;
	reg [63:0] r_cache_hits;
	function [31:0] select_cl32;
		input reg [127:0] cl;
		input reg [1:0] pos;
		reg [31:0] w32;
		begin
			case (pos)
				2'd0: w32 = cl[31:0];
				2'd1: w32 = cl[63:32];
				2'd2: w32 = cl[95:64];
				2'd3: w32 = cl[127:96];
			endcase
			select_cl32 = w32;
		end
	endfunction
	function [63:0] select_jal_simm;
		input reg [127:0] cl;
		input reg [1:0] pos;
		localparam PP = 32;
		reg [31:0] w32;
		begin
			case (pos)
				2'd0: w32 = cl[31:0];
				2'd1: w32 = cl[63:32];
				2'd2: w32 = cl[95:64];
				2'd3: w32 = cl[127:96];
			endcase
			select_jal_simm = {{43 {w32[31]}}, w32[31], w32[19:12], w32[20], w32[30:21], 1'b0};
		end
	endfunction
	function [63:0] select_br_simm;
		input reg [127:0] cl;
		input reg [1:0] pos;
		localparam PP = 32;
		reg [31:0] w32;
		begin
			case (pos)
				2'd0: w32 = cl[31:0];
				2'd1: w32 = cl[63:32];
				2'd2: w32 = cl[95:64];
				2'd3: w32 = cl[127:96];
			endcase
			select_br_simm = {{51 {w32[31]}}, w32[31], w32[7], w32[30:25], w32[11:8], 1'b0};
		end
	endfunction
	function [2:0] select_pd;
		input reg [11:0] cl;
		input reg [1:0] pos;
		reg [2:0] j;
		begin
			case (pos)
				2'd0: j = cl[2:0];
				2'd1: j = cl[5:3];
				2'd2: j = cl[8:6];
				2'd3: j = cl[11:9];
			endcase
			select_pd = j;
		end
	endfunction
	reg [63:0] r_pc;
	reg [63:0] n_pc;
	reg [63:0] r_miss_pc;
	reg [63:0] n_miss_pc;
	reg [63:0] r_cache_pc;
	reg [63:0] n_cache_pc;
	reg [63:0] r_btb_pc;
	wire [63:0] w_cache_pc4 = r_cache_pc + 'd4;
	wire [63:0] w_cache_pc8 = r_cache_pc + 'd8;
	wire [63:0] w_cache_pc12 = r_cache_pc + 'd12;
	wire [63:0] w_cache_pc16 = r_cache_pc + 'd16;
	wire [63:0] w_cache_pc20 = r_cache_pc + 'd20;
	reg [3:0] n_state;
	reg [3:0] r_state;
	assign l1i_state = r_state;
	reg r_restart_req;
	reg n_restart_req;
	reg r_restart_ack;
	reg n_restart_ack;
	reg r_req;
	reg n_req;
	wire w_valid_out0;
	wire w_valid_out1;
	reg t_miss;
	reg t_hit;
	reg t_push_insn;
	reg t_push_insn2;
	reg t_push_insn3;
	reg t_push_insn4;
	reg t_unaligned_fetch;
	reg n_page_fault;
	reg r_page_fault;
	reg n_tlb_miss;
	reg r_tlb_miss;
	wire [31:0] w_tlb_pc;
	wire w_tlb_hit;
	reg t_reload_tlb;
	reg t_clear_fq;
	reg r_flush_req;
	reg n_flush_req;
	reg r_flush_complete;
	reg n_flush_complete;
	reg t_take_br;
	reg t_is_cflow;
	reg t_take_br0;
	reg t_take_br1;
	reg t_take_br2;
	reg t_take_br3;
	reg t_update_spec_hist;
	reg [31:0] t_insn_data;
	reg [31:0] t_insn_data2;
	reg [31:0] t_insn_data3;
	reg [31:0] t_insn_data4;
	reg [63:0] t_jal_simm;
	reg [63:0] t_br_simm;
	reg t_is_call;
	reg t_is_ret;
	reg [63:0] t_ret_pc;
	reg [4:0] t_spec_branch_marker;
	reg [3:0] t_branch_marker;
	reg [3:0] t_any_branch;
	reg [2:0] t_first_branch;
	reg [2:0] t_taken_branch_idx;
	reg [63:0] r_branch_pc;
	reg t_init_pht;
	reg t_init_rsb;
	reg [15:0] r_init_pht_idx;
	reg [15:0] n_init_pht_idx;
	localparam PP = 32;
	localparam SEXT = 48;
	reg [177:0] t_insn;
	reg [177:0] t_insn2;
	reg [177:0] t_insn3;
	reg [177:0] t_insn4;
	reg [2:0] t_pd;
	reg [2:0] t_first_pd;
	reg [2:0] t_pd0;
	reg [2:0] t_pd1;
	reg [2:0] t_pd2;
	reg [2:0] t_pd3;
	reg t_tcb0;
	reg t_tcb1;
	reg t_tcb2;
	reg t_tcb3;
	reg t_br0;
	reg t_br1;
	reg t_br2;
	reg t_br3;
	reg [63:0] r_cycle;
	always @(posedge clk) r_cycle <= (reset ? 'd0 : r_cycle + 'd1);
	assign flush_complete = r_flush_complete;
	assign insn_valid = !fq_empty;
	assign insn_valid_two = !(fq_next_empty || fq_empty);
	assign restart_ack = r_restart_ack;
	assign mem_req_valid = r_mem_req_valid;
	assign mem_req_addr = r_mem_req_addr[31:0];
	assign mem_req_opcode = 4'd4;
	assign cache_hits = r_cache_hits;
	assign cache_accesses = r_cache_accesses;
	assign page_walk_req_valid = r_tlb_miss;
	assign page_walk_req_va = r_miss_pc;
	wire [63:0] w_restart_pc = restart_pc;
	always @(*) begin
		if (_sv2v_0)
			;
		n_fq_tail_ptr = r_fq_tail_ptr;
		n_fq_head_ptr = r_fq_head_ptr;
		n_fq_next_head_ptr = r_fq_next_head_ptr;
		n_fq_next_tail_ptr = r_fq_next_tail_ptr;
		n_fq_next3_tail_ptr = r_fq_next3_tail_ptr;
		n_fq_next4_tail_ptr = r_fq_next4_tail_ptr;
		fq_empty = r_fq_head_ptr == r_fq_tail_ptr;
		fq_next_empty = r_fq_next_head_ptr == r_fq_tail_ptr;
		fq_full = (r_fq_head_ptr != r_fq_tail_ptr) && (r_fq_head_ptr[2:0] == r_fq_tail_ptr[2:0]);
		fq_full2 = ((r_fq_head_ptr != r_fq_next_tail_ptr) && (r_fq_head_ptr[2:0] == r_fq_next_tail_ptr[2:0])) || fq_full;
		fq_full3 = ((r_fq_head_ptr != r_fq_next3_tail_ptr) && (r_fq_head_ptr[2:0] == r_fq_next3_tail_ptr[2:0])) || fq_full2;
		fq_full4 = ((r_fq_head_ptr != r_fq_next4_tail_ptr) && (r_fq_head_ptr[2:0] == r_fq_next4_tail_ptr[2:0])) || fq_full3;
		insn = r_fq[r_fq_head_ptr[2:0]];
		insn_two = r_fq[r_fq_next_head_ptr[2:0]];
		if (t_push_insn4) begin
			n_fq_tail_ptr = r_fq_tail_ptr + 'd4;
			n_fq_next_tail_ptr = r_fq_next_tail_ptr + 'd4;
			n_fq_next3_tail_ptr = r_fq_next3_tail_ptr + 'd4;
			n_fq_next4_tail_ptr = r_fq_next4_tail_ptr + 'd4;
		end
		else if (t_push_insn3) begin
			n_fq_tail_ptr = r_fq_tail_ptr + 'd3;
			n_fq_next_tail_ptr = r_fq_next_tail_ptr + 'd3;
			n_fq_next3_tail_ptr = r_fq_next3_tail_ptr + 'd3;
			n_fq_next4_tail_ptr = r_fq_next4_tail_ptr + 'd3;
		end
		else if (t_push_insn2) begin
			n_fq_tail_ptr = r_fq_tail_ptr + 'd2;
			n_fq_next_tail_ptr = r_fq_next_tail_ptr + 'd2;
			n_fq_next3_tail_ptr = r_fq_next3_tail_ptr + 'd2;
			n_fq_next4_tail_ptr = r_fq_next4_tail_ptr + 'd2;
		end
		else if (t_push_insn) begin
			n_fq_tail_ptr = r_fq_tail_ptr + 'd1;
			n_fq_next_tail_ptr = r_fq_next_tail_ptr + 'd1;
			n_fq_next3_tail_ptr = r_fq_next3_tail_ptr + 'd1;
			n_fq_next4_tail_ptr = r_fq_next4_tail_ptr + 'd1;
		end
		if (insn_ack && !insn_ack_two) begin
			n_fq_head_ptr = r_fq_head_ptr + 'd1;
			n_fq_next_head_ptr = r_fq_next_head_ptr + 'd1;
		end
		else if (insn_ack && insn_ack_two) begin
			n_fq_head_ptr = r_fq_head_ptr + 'd2;
			n_fq_next_head_ptr = r_fq_next_head_ptr + 'd2;
		end
	end
	always @(posedge clk)
		if (t_push_insn)
			r_fq[r_fq_tail_ptr[2:0]] <= t_insn;
		else if (t_push_insn2) begin
			r_fq[r_fq_tail_ptr[2:0]] <= t_insn;
			r_fq[r_fq_next_tail_ptr[2:0]] <= t_insn2;
		end
		else if (t_push_insn3) begin
			r_fq[r_fq_tail_ptr[2:0]] <= t_insn;
			r_fq[r_fq_next_tail_ptr[2:0]] <= t_insn2;
			r_fq[r_fq_next3_tail_ptr[2:0]] <= t_insn3;
		end
		else if (t_push_insn4) begin
			r_fq[r_fq_tail_ptr[2:0]] <= t_insn;
			r_fq[r_fq_next_tail_ptr[2:0]] <= t_insn2;
			r_fq[r_fq_next3_tail_ptr[2:0]] <= t_insn3;
			r_fq[r_fq_next4_tail_ptr[2:0]] <= t_insn4;
		end
	always @(posedge clk)
		if (r_state == 4'd7)
			r_btb[r_init_pht_idx[6:0]] <= 64'd0;
		else if (branch_pc_is_indirect & branch_pc_valid)
			r_btb[branch_pht_idx[6:0]] <= target_pc;
	always @(posedge clk) r_btb_pc <= (reset ? 'd0 : r_btb[n_pht_idx[6:0]]);
	wire w_hit0 = (w_valid_out0 ? w_tag_out0 == w_tlb_pc[31:IDX_STOP] : 1'b0);
	wire w_hit1 = (w_valid_out1 ? w_tag_out1 == w_tlb_pc[31:IDX_STOP] : 1'b0);
	wire w_hit = w_hit0 | w_hit1;
	wire [127:0] w_array = (w_hit0 ? w_array_out0 : w_array_out1);
	wire [11:0] w_jump = (w_hit0 ? w_jump_out0 : w_jump_out1);
	reg r_reload;
	reg n_reload;
	reg [63:0] t_br_disp;
	reg [63:0] t_j_disp;
	reg [15:0] n_wait_cycles;
	reg [15:0] r_wait_cycles;
	always @(posedge clk) r_wait_cycles <= (reset ? 'd0 : n_wait_cycles);
	always @(*) begin
		if (_sv2v_0)
			;
		n_wait_cycles = r_wait_cycles;
		n_page_fault = r_page_fault;
		n_pc = r_pc;
		n_miss_pc = r_miss_pc;
		n_cache_pc = 'd0;
		n_state = r_state;
		n_reload = r_reload;
		n_restart_ack = 1'b0;
		n_flush_req = r_flush_req | flush_req;
		n_flush_complete = 1'b0;
		t_cache_idx = 'd0;
		t_cache_tag = 'd0;
		n_req = 1'b0;
		n_mem_req_valid = 1'b0;
		n_mem_req_addr = r_mem_req_addr;
		n_resteer_bubble = 1'b0;
		t_next_spec_rs_tos = r_spec_rs_tos + 'd1;
		n_restart_req = restart_valid | r_restart_req;
		t_miss = r_req && !w_hit;
		t_hit = r_req && w_hit;
		t_insn_idx = r_cache_pc[3:WORD_START];
		t_pd = select_pd(w_jump, t_insn_idx);
		t_pd0 = select_pd(w_jump, 'd0);
		t_pd1 = select_pd(w_jump, 'd1);
		t_pd2 = select_pd(w_jump, 'd2);
		t_pd3 = select_pd(w_jump, 'd3);
		t_br0 = t_pd0 != 3'd0;
		t_br1 = t_pd1 != 3'd0;
		t_br2 = t_pd2 != 3'd0;
		t_br3 = t_pd3 != 3'd0;
		t_insn_data = select_cl32(w_array, t_insn_idx);
		t_insn_data2 = select_cl32(w_array, t_insn_idx + 2'd1);
		t_insn_data3 = select_cl32(w_array, t_insn_idx + 2'd2);
		t_insn_data4 = select_cl32(w_array, t_insn_idx + 2'd3);
		r_pht_out = (t_insn_idx == 2'd0 ? r_pht_out_vec[1:0] : (t_insn_idx == 2'd1 ? r_pht_out_vec[3:2] : (t_insn_idx == 2'd2 ? r_pht_out_vec[5:4] : r_pht_out_vec[7:6])));
		t_tcb0 = (((t_pd0 == 3'd1) & (r_pht_out_vec[1] == 1'b0)) | (t_pd0 == 3'd0)) == 1'b0;
		t_tcb1 = (((t_pd1 == 3'd1) & (r_pht_out_vec[3] == 1'b0)) | (t_pd1 == 3'd0)) == 1'b0;
		t_tcb2 = (((t_pd2 == 3'd1) & (r_pht_out_vec[5] == 1'b0)) | (t_pd2 == 3'd0)) == 1'b0;
		t_tcb3 = (((t_pd3 == 3'd1) & (r_pht_out_vec[7] == 1'b0)) | (t_pd3 == 3'd0)) == 1'b0;
		t_spec_branch_marker = {1'b1, t_tcb3, t_tcb2, t_tcb1, t_tcb0} >> t_insn_idx;
		t_branch_marker = {t_tcb3, t_tcb2, t_tcb1, t_tcb0} >> t_insn_idx;
		t_any_branch = {t_br3, t_br2, t_br1, t_br0} >> t_insn_idx;
		t_taken_branch_idx = 'd7;
		casez (t_branch_marker)
			4'bzzz1: t_taken_branch_idx = 'd0;
			4'bzz10: t_taken_branch_idx = 'd1;
			4'bz100: t_taken_branch_idx = 'd2;
			4'b1000: t_taken_branch_idx = 'd3;
			default: t_taken_branch_idx = 'd7;
		endcase
		t_first_branch = 'd0;
		casez (t_spec_branch_marker)
			5'bzzzz1: t_first_branch = 'd0;
			5'bzzz10: t_first_branch = 'd1;
			5'bzz100: t_first_branch = 'd2;
			5'bz1000: t_first_branch = 'd3;
			5'b10000: t_first_branch = 'd4;
			default: t_first_branch = 'd7;
		endcase
		t_branch_idx = t_taken_branch_idx[1:0] + t_insn_idx;
		t_pht_out = (t_branch_idx == 'd0 ? r_pht_out_vec[1:0] : (t_branch_idx == 'd1 ? r_pht_out_vec[3:2] : (t_branch_idx == 'd2 ? r_pht_out_vec[5:4] : r_pht_out_vec[7:6])));
		t_first_pd = select_pd(w_jump, t_branch_idx);
		t_jal_simm = {{43 {t_insn_data[31]}}, t_insn_data[31], t_insn_data[19:12], t_insn_data[20], t_insn_data[30:21], 1'b0};
		t_br_simm = {{51 {t_insn_data[31]}}, t_insn_data[31], t_insn_data[7], t_insn_data[30:25], t_insn_data[11:8], 1'b0};
		t_br_disp = select_br_simm(w_array, t_branch_idx);
		t_j_disp = select_jal_simm(w_array, t_branch_idx);
		t_clear_fq = 1'b0;
		t_push_insn = 1'b0;
		t_push_insn2 = 1'b0;
		t_push_insn3 = 1'b0;
		t_push_insn4 = 1'b0;
		t_unaligned_fetch = 1'b0;
		t_take_br = 1'b0;
		t_take_br0 = 1'b0;
		t_take_br1 = 1'b0;
		t_take_br2 = 1'b0;
		t_take_br3 = 1'b0;
		t_is_cflow = 1'b0;
		t_update_spec_hist = 1'b0;
		t_is_call = 1'b0;
		t_ret_pc = w_cache_pc4;
		t_is_ret = 1'b0;
		t_init_pht = 1'b0;
		t_init_rsb = 1'b0;
		n_init_pht_idx = r_init_pht_idx;
		t_reload_tlb = 1'b0;
		n_tlb_miss = 1'b0;
		case (r_state)
			4'd0: n_state = 4'd7;
			4'd7: begin
				t_init_pht = 1'b1;
				t_init_rsb = 1'b1;
				n_init_pht_idx = r_init_pht_idx + 'd1;
				if (r_init_pht_idx == 65535) begin
					n_state = 4'd5;
					t_cache_idx = 0;
				end
			end
			4'd1:
				if (n_restart_req) begin
					n_restart_ack = 1'b1;
					n_restart_req = 1'b0;
					n_pc = w_restart_pc;
					n_state = 4'd2;
					t_clear_fq = 1'b1;
				end
			4'd2: begin
				t_cache_idx = r_pc[11:IDX_START];
				t_cache_tag = r_pc[31:IDX_STOP];
				n_cache_pc = r_pc;
				n_req = 1'b1;
				n_pc = r_pc + 'd4;
				if (r_resteer_bubble)
					;
				else if (n_flush_req) begin
					n_flush_req = 1'b0;
					t_clear_fq = 1'b1;
					n_state = 4'd5;
					t_cache_idx = 0;
				end
				else if (n_restart_req) begin
					n_restart_ack = 1'b1;
					n_restart_req = 1'b0;
					n_pc = w_restart_pc;
					n_req = 1'b0;
					n_state = 4'd2;
					t_clear_fq = 1'b1;
					n_page_fault = 1'b0;
				end
				else if (r_page_fault) begin
					if (!fq_full) begin
						n_page_fault = 1'b0;
						t_push_insn = 1'b1;
					end
				end
				else if ((!w_tlb_hit & r_req) && paging_active) begin
					n_state = 4'd8;
					n_pc = r_pc;
					n_miss_pc = r_cache_pc;
					n_tlb_miss = 1'b1;
				end
				else if (t_miss) begin
					n_state = 4'd3;
					n_mem_req_addr = (paging_active ? {32'd0, w_tlb_pc[31:4], {4 {1'b0}}} : {r_cache_pc[63:4], {4 {1'b0}}});
					n_mem_req_valid = 1'b1;
					n_miss_pc = r_cache_pc;
					n_pc = r_pc;
					n_reload = r_cycle[0];
				end
				else if (t_hit && !fq_full) begin
					if (((t_taken_branch_idx == 'd3) & !fq_full4) & ((t_first_pd == 3'd1) | (t_first_pd == 3'd3))) begin
						t_update_spec_hist = 1'b1;
						t_push_insn4 = 1'b1;
						t_is_cflow = 1'b1;
						t_take_br = 1;
						n_pc = w_cache_pc12 + (t_first_pd == 3'd3 ? t_j_disp : t_br_disp);
					end
					else if (((t_taken_branch_idx == 'd2) & !fq_full3) & ((t_first_pd == 3'd1) | (t_first_pd == 3'd3))) begin
						t_update_spec_hist = 1'b1;
						t_push_insn3 = 1'b1;
						t_is_cflow = 1'b1;
						t_take_br = 1;
						n_pc = w_cache_pc8 + (t_first_pd == 'd3 ? t_j_disp : t_br_disp);
					end
					else if (((t_taken_branch_idx == 'd1) & !fq_full2) & ((t_first_pd == 3'd1) | (t_first_pd == 3'd3))) begin
						t_update_spec_hist = 1'b1;
						t_push_insn2 = 1'b1;
						t_is_cflow = 1'b1;
						t_take_br = 1;
						n_pc = w_cache_pc4 + (t_first_pd == 'd3 ? t_j_disp : t_br_disp);
					end
					else begin
						t_update_spec_hist = t_pd != 3'd0;
						if ((t_pd == 3'd5) || (t_pd == 3'd3)) begin
							t_is_cflow = 1'b1;
							t_take_br = 1;
							t_is_call = t_pd == 3'd5;
							n_pc = r_cache_pc + t_jal_simm;
							t_push_insn = 1'b1;
						end
						else if ((t_pd == 3'd1) && r_pht_out[1]) begin
							t_is_cflow = 1'b1;
							t_take_br = 1;
							n_pc = r_cache_pc + t_br_simm;
							t_push_insn = 1'b1;
						end
						else if (t_pd == 3'd2) begin
							t_is_cflow = 1'b1;
							t_is_ret = 1'b1;
							t_take_br = 1'b1;
							n_pc = r_spec_return_stack[t_next_spec_rs_tos * 64+:64];
							t_push_insn = 1'b1;
						end
						else if ((t_pd == 3'd4) || (t_pd == 3'd6)) begin
							t_is_cflow = 1'b1;
							t_take_br = 1'b1;
							t_is_call = t_pd == 3'd6;
							n_pc = r_btb_pc;
							t_push_insn = 1'b1;
						end
					end
					n_resteer_bubble = t_is_cflow;
					if (t_is_cflow == 1'b0) begin
						if ((t_first_branch == 'd4) && !fq_full4) begin
							t_push_insn4 = 1'b1;
							t_cache_idx = r_cache_idx + 'd1;
							n_cache_pc = w_cache_pc16;
							t_cache_tag = n_cache_pc[31:IDX_STOP];
							n_pc = w_cache_pc20;
							t_update_spec_hist = |t_any_branch;
						end
						else if ((t_first_branch == 'd3) && !fq_full3) begin
							t_push_insn3 = 1'b1;
							n_cache_pc = w_cache_pc12;
							n_pc = w_cache_pc16;
							t_cache_tag = n_cache_pc[31:IDX_STOP];
							t_update_spec_hist = |t_any_branch;
							if (t_insn_idx != 0)
								t_cache_idx = r_cache_idx + 'd1;
						end
						else if ((t_first_branch == 'd2) && !fq_full2) begin
							t_push_insn2 = 1'b1;
							n_cache_pc = w_cache_pc8;
							t_cache_tag = n_cache_pc[31:IDX_STOP];
							n_pc = w_cache_pc12;
							t_update_spec_hist = |t_any_branch;
							if (t_insn_idx == 2)
								t_cache_idx = r_cache_idx + 'd1;
						end
						else
							t_push_insn = 1'b1;
					end
				end
				else if (t_hit && fq_full) begin
					n_pc = r_pc;
					n_miss_pc = r_cache_pc;
					n_state = 4'd6;
				end
			end
			4'd3: begin
				n_wait_cycles = r_wait_cycles + 'd1;
				if (&r_wait_cycles) begin
					$display("icache fetch request for %x timed out at cycle %d, r_miss_pc %x, phys addr %x, cycles %d", r_pc, r_cycle, r_miss_pc, r_mem_req_addr, r_wait_cycles);
					$stop;
				end
				if (mem_rsp_valid) begin
					n_state = 4'd4;
					n_wait_cycles = 'd0;
				end
			end
			4'd4: begin
				t_cache_idx = r_miss_pc[11:IDX_START];
				t_cache_tag = r_miss_pc[31:IDX_STOP];
				if (n_flush_req) begin
					n_flush_req = 1'b0;
					t_clear_fq = 1'b1;
					n_state = 4'd5;
					t_cache_idx = 0;
				end
				else if (n_restart_req) begin
					n_restart_ack = 1'b1;
					n_restart_req = 1'b0;
					n_pc = w_restart_pc;
					n_req = 1'b0;
					n_state = 4'd2;
					t_clear_fq = 1'b1;
					n_page_fault = 1'b0;
				end
				else if (!fq_full) begin
					n_cache_pc = r_miss_pc;
					n_req = 1'b1;
					n_state = 4'd2;
				end
			end
			4'd5: begin
				if (r_cache_idx == 255) begin
					n_flush_complete = 1'b1;
					n_state = 4'd1;
				end
				t_cache_idx = r_cache_idx + 'd1;
			end
			4'd6: begin
				t_cache_idx = r_miss_pc[11:IDX_START];
				t_cache_tag = r_miss_pc[31:IDX_STOP];
				n_cache_pc = r_miss_pc;
				if (n_flush_req) begin
					n_flush_req = 1'b0;
					t_clear_fq = 1'b1;
					n_state = 4'd5;
					t_cache_idx = 0;
				end
				else if (!fq_full) begin
					n_req = 1'b1;
					n_state = 4'd2;
				end
				else if (n_restart_req) begin
					n_restart_ack = 1'b1;
					n_restart_req = 1'b0;
					n_pc = w_restart_pc;
					n_req = 1'b0;
					n_state = 4'd2;
					t_clear_fq = 1'b1;
					n_page_fault = 1'b0;
				end
			end
			4'd8:
				if (page_walk_rsp_valid) begin
					n_page_fault = page_walk_rsp[71];
					t_reload_tlb = page_walk_rsp[71] == 1'b0;
					n_state = 4'd9;
				end
			4'd9: begin
				n_cache_pc = r_miss_pc;
				t_cache_idx = r_miss_pc[11:IDX_START];
				t_cache_tag = r_miss_pc[31:IDX_STOP];
				n_state = 4'd2;
				n_req = 1'b1;
			end
			default:
				;
		endcase
	end
	always @(*) begin
		if (_sv2v_0)
			;
		n_cache_accesses = r_cache_accesses;
		n_cache_hits = r_cache_hits;
		if (t_hit)
			n_cache_hits = r_cache_hits + 'd1;
		if (r_req)
			n_cache_accesses = r_cache_accesses + 'd1;
	end
	always @(*) begin
		if (_sv2v_0)
			;
		t_insn[177-:32] = t_insn_data;
		t_insn[145] = r_page_fault;
		t_insn[144-:64] = r_cache_pc;
		t_insn[80-:64] = n_pc;
		t_insn[16] = t_taken_branch_idx == 'd0;
		t_insn[15-:16] = r_pht_idx;
		t_insn2[177-:32] = t_insn_data2;
		t_insn2[145] = 1'b0;
		t_insn2[144-:64] = w_cache_pc4;
		t_insn2[80-:64] = n_pc;
		t_insn2[16] = t_taken_branch_idx == 'd1;
		t_insn2[15-:16] = r_pht_idx;
		t_insn3[177-:32] = t_insn_data3;
		t_insn3[145] = 1'b0;
		t_insn3[144-:64] = w_cache_pc8;
		t_insn3[80-:64] = n_pc;
		t_insn3[16] = t_taken_branch_idx == 'd2;
		t_insn3[15-:16] = r_pht_idx;
		t_insn4[177-:32] = t_insn_data4;
		t_insn4[145] = 1'b0;
		t_insn4[144-:64] = w_cache_pc12;
		t_insn4[80-:64] = n_pc;
		t_insn4[16] = t_taken_branch_idx == 'd3;
		t_insn4[15-:16] = r_pht_idx;
	end
	reg t_wr_valid_ram_en0;
	reg t_wr_valid_ram_en1;
	reg t_valid_ram_value0;
	reg t_valid_ram_value1;
	reg t_last_ram_value;
	reg t_last_ram_en;
	reg [7:0] t_valid_ram_idx;
	always @(*) begin
		if (_sv2v_0)
			;
		t_last_ram_en = r_req || (r_state == 4'd5);
		t_last_ram_value = w_hit1;
	end
	compute_pht_idx cpi0(
		.pc({n_cache_pc[63:4], 4'd0}),
		.hist(r_spec_gbl_hist),
		.idx(n_pht_idx)
	);
	reg r_print_pht;
	always @(posedge clk) r_print_pht <= (reset ? 1'b0 : n_cache_pc[63:4] == 60'h000000000001099);
	always @(*) begin
		if (_sv2v_0)
			;
		t_wr_valid_ram_en0 = (mem_rsp_valid && (r_reload == 1'b0)) || (r_state == 4'd5);
		t_wr_valid_ram_en1 = (mem_rsp_valid && (r_reload == 1'b1)) || (r_state == 4'd5);
		t_valid_ram_value0 = r_state != 4'd5;
		t_valid_ram_value1 = r_state != 4'd5;
		t_valid_ram_idx = (mem_rsp_valid ? r_mem_req_addr[11:IDX_START] : r_cache_idx);
	end
	always @(*) begin
		if (_sv2v_0)
			;
		t_pht_val = 'd0;
		case (r_branch_pc[3:2])
			2'd0: t_pht_val = r_pht_update_out[1:0];
			2'd1: t_pht_val = r_pht_update_out[3:2];
			2'd2: t_pht_val = r_pht_update_out[5:4];
			2'd3: t_pht_val = r_pht_update_out[7:6];
		endcase
		t_do_pht_wr = r_pht_update;
		case (t_pht_val)
			2'd0:
				if (r_take_br)
					t_pht_val = 2'd1;
				else
					t_do_pht_wr = 1'b0;
			2'd1: t_pht_val = (r_take_br ? 2'd2 : 2'd0);
			2'd2: t_pht_val = (r_take_br ? 2'd3 : 2'd1);
			2'd3:
				if (!r_take_br)
					t_pht_val = 2'd2;
				else
					t_do_pht_wr = 1'b0;
		endcase
		t_pht_val_vec = 8'd0;
		case (r_branch_pc[3:2])
			2'd0: t_pht_val_vec = {r_pht_update_out[7:2], t_pht_val};
			2'd1: t_pht_val_vec = {r_pht_update_out[7:4], t_pht_val, r_pht_update_out[1:0]};
			2'd2: t_pht_val_vec = {r_pht_update_out[7:6], t_pht_val, r_pht_update_out[3:0]};
			2'd3: t_pht_val_vec = {t_pht_val, r_pht_update_out[5:0]};
		endcase
	end
	always @(posedge clk)
		if (reset) begin
			r_pht_idx <= 'd0;
			r_last_spec_gbl_hist <= 'd0;
			r_pht_update <= 1'b0;
			r_pht_update_idx <= 'd0;
			r_take_br <= 1'b0;
			r_branch_pc <= 'd0;
		end
		else begin
			r_pht_idx <= n_pht_idx;
			r_last_spec_gbl_hist <= r_spec_gbl_hist;
			r_pht_update <= branch_pc_valid;
			r_pht_update_idx <= branch_pht_idx;
			r_take_br <= took_branch;
			r_branch_pc <= branch_pc;
		end
	tlb #(
		.LG_N(4),
		.ISIDE(1)
	) itlb(
		.clk(clk),
		.reset(reset),
		.priv(priv),
		.clear(clear_tlb),
		.active(paging_active),
		.req(n_req),
		.va(n_cache_pc),
		.pa(w_tlb_pc),
		.hit(w_tlb_hit),
		.dirty(),
		.readable(),
		.writable(),
		.user(),
		.zero_page(),
		.tlb_hits(tlb_hits),
		.tlb_accesses(tlb_accesses),
		.replace_va(r_miss_pc),
		.replace(t_reload_tlb),
		.page_walk_rsp(page_walk_rsp)
	);
	ram1r1w #(
		.WIDTH(1),
		.LG_DEPTH(8)
	) last_array(
		.clk(clk),
		.rd_addr(t_cache_idx),
		.wr_addr(t_cache_idx),
		.wr_data(t_last_ram_value),
		.wr_en(t_last_ram_en),
		.rd_data(w_last_out)
	);
	ram2r1w #(
		.WIDTH(8),
		.LG_DEPTH(16)
	) pht0(
		.clk(clk),
		.rd_addr0(n_pht_idx),
		.rd_addr1(branch_pht_idx),
		.wr_addr((t_init_pht ? r_init_pht_idx : r_pht_update_idx)),
		.wr_data((t_init_pht ? 8'b01010101 : t_pht_val_vec)),
		.wr_en(t_init_pht || t_do_pht_wr),
		.rd_data0(r_pht_out_vec),
		.rd_data1(r_pht_update_out)
	);
	ram1r1w #(
		.WIDTH(1),
		.LG_DEPTH(8)
	) valid_array0(
		.clk(clk),
		.rd_addr(t_cache_idx),
		.wr_addr(t_valid_ram_idx),
		.wr_data(t_valid_ram_value0),
		.wr_en(t_wr_valid_ram_en0),
		.rd_data(w_valid_out0)
	);
	ram1r1w #(
		.WIDTH(N_TAG_BITS),
		.LG_DEPTH(8)
	) tag_array0(
		.clk(clk),
		.rd_addr(t_cache_idx),
		.wr_addr(r_mem_req_addr[11:IDX_START]),
		.wr_data(r_mem_req_addr[31:IDX_STOP]),
		.wr_en(mem_rsp_valid & (r_reload == 1'b0)),
		.rd_data(w_tag_out0)
	);
	ram1r1w #(
		.WIDTH(L1I_CL_LEN_BITS),
		.LG_DEPTH(8)
	) insn_array0(
		.clk(clk),
		.rd_addr(t_cache_idx),
		.wr_addr(r_mem_req_addr[11:IDX_START]),
		.wr_data({mem_rsp_load_data[127:96], mem_rsp_load_data[95:64], mem_rsp_load_data[63:32], mem_rsp_load_data[31:0]}),
		.wr_en(mem_rsp_valid & (r_reload == 1'b0)),
		.rd_data(w_array_out0)
	);
	ram1r1w #(
		.WIDTH(1),
		.LG_DEPTH(8)
	) valid_array1(
		.clk(clk),
		.rd_addr(t_cache_idx),
		.wr_addr(t_valid_ram_idx),
		.wr_data(t_valid_ram_value1),
		.wr_en(t_wr_valid_ram_en1),
		.rd_data(w_valid_out1)
	);
	ram1r1w #(
		.WIDTH(N_TAG_BITS),
		.LG_DEPTH(8)
	) tag_array1(
		.clk(clk),
		.rd_addr(t_cache_idx),
		.wr_addr(r_mem_req_addr[11:IDX_START]),
		.wr_data(r_mem_req_addr[31:IDX_STOP]),
		.wr_en(mem_rsp_valid & (r_reload == 1'b1)),
		.rd_data(w_tag_out1)
	);
	ram1r1w #(
		.WIDTH(L1I_CL_LEN_BITS),
		.LG_DEPTH(8)
	) insn_array1(
		.clk(clk),
		.rd_addr(t_cache_idx),
		.wr_addr(r_mem_req_addr[11:IDX_START]),
		.wr_data({mem_rsp_load_data[127:96], mem_rsp_load_data[95:64], mem_rsp_load_data[63:32], mem_rsp_load_data[31:0]}),
		.wr_en(mem_rsp_valid & (r_reload == 1'b1)),
		.rd_data(w_array_out1)
	);
	wire [2:0] w_pd0;
	wire [2:0] w_pd1;
	wire [2:0] w_pd2;
	wire [2:0] w_pd3;
	predecode pd0(
		.insn(mem_rsp_load_data[31:0]),
		.pd(w_pd0)
	);
	predecode pd1(
		.insn(mem_rsp_load_data[63:32]),
		.pd(w_pd1)
	);
	predecode pd2(
		.insn(mem_rsp_load_data[95:64]),
		.pd(w_pd2)
	);
	predecode pd3(
		.insn(mem_rsp_load_data[127:96]),
		.pd(w_pd3)
	);
	ram1r1w #(
		.WIDTH(12),
		.LG_DEPTH(8)
	) pd_data0(
		.clk(clk),
		.rd_addr(t_cache_idx),
		.wr_addr(r_mem_req_addr[11:IDX_START]),
		.wr_data({w_pd3, w_pd2, w_pd1, w_pd0}),
		.wr_en(mem_rsp_valid & (r_reload == 1'b0)),
		.rd_data(w_jump_out0)
	);
	ram1r1w #(
		.WIDTH(12),
		.LG_DEPTH(8)
	) pd_data1(
		.clk(clk),
		.rd_addr(t_cache_idx),
		.wr_addr(r_mem_req_addr[11:IDX_START]),
		.wr_data({w_pd3, w_pd2, w_pd1, w_pd0}),
		.wr_en(mem_rsp_valid & (r_reload == 1'b1)),
		.rd_data(w_jump_out1)
	);
	always @(*) begin
		if (_sv2v_0)
			;
		n_spec_rs_tos = r_spec_rs_tos;
		if (t_init_rsb)
			n_spec_rs_tos = r_spec_rs_tos + 'd1;
		else if (n_restart_ack)
			n_spec_rs_tos = r_arch_rs_tos;
		else if (t_is_call)
			n_spec_rs_tos = r_spec_rs_tos - 'd1;
		else if (t_is_ret)
			n_spec_rs_tos = r_spec_rs_tos + 'd1;
	end
	always @(posedge clk)
		if (t_init_rsb)
			r_spec_return_stack[r_spec_rs_tos * 64+:64] <= 64'd0;
		else if (t_is_call)
			r_spec_return_stack[r_spec_rs_tos * 64+:64] <= t_ret_pc;
		else if (n_restart_ack)
			r_spec_return_stack <= r_arch_return_stack;
	always @(posedge clk)
		if (t_init_rsb)
			r_arch_return_stack[r_arch_rs_tos * 64+:64] <= 64'd0;
		else if ((retire_reg_valid && retire_valid) && retired_call)
			r_arch_return_stack[r_arch_rs_tos * 64+:64] <= retire_reg_data;
	always @(*) begin
		if (_sv2v_0)
			;
		n_arch_rs_tos = r_arch_rs_tos;
		if (t_init_rsb)
			n_arch_rs_tos = r_arch_rs_tos + 'd1;
		else if (retire_valid && retired_call)
			n_arch_rs_tos = r_arch_rs_tos - 'd1;
		else if (retire_valid && retired_ret)
			n_arch_rs_tos = r_arch_rs_tos + 'd1;
	end
	always @(*) begin
		if (_sv2v_0)
			;
		n_spec_gbl_hist = r_spec_gbl_hist;
		if (n_restart_ack)
			n_spec_gbl_hist = n_arch_gbl_hist;
		else if (t_update_spec_hist)
			n_spec_gbl_hist = {r_spec_gbl_hist[14:0], t_take_br};
	end
	always @(*) begin
		if (_sv2v_0)
			;
		n_arch_gbl_hist = r_arch_gbl_hist;
		if (branch_pc_valid)
			n_arch_gbl_hist = {r_arch_gbl_hist[14:0], took_branch};
	end
	always @(posedge clk)
		if (reset) begin
			r_tlb_miss <= 1'b0;
			r_state <= 4'd0;
			r_reload <= 1'b0;
			r_page_fault <= 1'b0;
			r_init_pht_idx <= 'd0;
			r_pc <= 'd0;
			r_miss_pc <= 'd0;
			r_cache_pc <= 'd0;
			r_restart_ack <= 1'b0;
			r_cache_idx <= 'd0;
			r_cache_tag <= 'd0;
			r_req <= 1'b0;
			r_mem_req_valid <= 1'b0;
			r_mem_req_addr <= 'd0;
			r_fq_head_ptr <= 'd0;
			r_fq_next_head_ptr <= 'd1;
			r_fq_next_tail_ptr <= 'd1;
			r_fq_next3_tail_ptr <= 'd1;
			r_fq_next4_tail_ptr <= 'd1;
			r_fq_tail_ptr <= 'd0;
			r_restart_req <= 1'b0;
			r_flush_req <= 1'b0;
			r_flush_complete <= 1'b0;
			r_spec_rs_tos <= 7;
			r_arch_rs_tos <= 7;
			r_arch_gbl_hist <= 'd0;
			r_spec_gbl_hist <= 'd0;
			r_cache_hits <= 'd0;
			r_cache_accesses <= 'd0;
			r_resteer_bubble <= 1'b0;
		end
		else begin
			r_tlb_miss <= n_tlb_miss;
			r_state <= n_state;
			r_reload <= n_reload;
			r_page_fault <= n_page_fault;
			r_init_pht_idx <= n_init_pht_idx;
			r_pc <= n_pc;
			r_miss_pc <= n_miss_pc;
			r_cache_pc <= n_cache_pc;
			r_restart_ack <= n_restart_ack;
			r_cache_idx <= t_cache_idx;
			r_cache_tag <= t_cache_tag;
			r_req <= n_req;
			r_mem_req_valid <= n_mem_req_valid;
			r_mem_req_addr <= n_mem_req_addr;
			r_fq_head_ptr <= (t_clear_fq ? 'd0 : n_fq_head_ptr);
			r_fq_next_head_ptr <= (t_clear_fq ? 'd1 : n_fq_next_head_ptr);
			r_fq_next_tail_ptr <= (t_clear_fq ? 'd1 : n_fq_next_tail_ptr);
			r_fq_next3_tail_ptr <= (t_clear_fq ? 'd2 : n_fq_next3_tail_ptr);
			r_fq_next4_tail_ptr <= (t_clear_fq ? 'd3 : n_fq_next4_tail_ptr);
			r_fq_tail_ptr <= (t_clear_fq ? 'd0 : n_fq_tail_ptr);
			r_restart_req <= n_restart_req;
			r_flush_req <= n_flush_req;
			r_flush_complete <= n_flush_complete;
			r_spec_rs_tos <= n_spec_rs_tos;
			r_arch_rs_tos <= n_arch_rs_tos;
			r_arch_gbl_hist <= n_arch_gbl_hist;
			r_spec_gbl_hist <= n_spec_gbl_hist;
			r_cache_hits <= n_cache_hits;
			r_cache_accesses <= n_cache_accesses;
			r_resteer_bubble <= n_resteer_bubble;
		end
	initial _sv2v_0 = 0;
endmodule

module mmu (
	clk,
	reset,
	clear_tlb,
	page_table_root,
	l1i_req,
	l1i_va,
	l1d_req,
	l1d_st,
	l1d_va,
	mem_req_valid,
	mem_req_addr,
	mem_req_data,
	mem_req_store,
	mem_rsp_valid,
	mem_rsp_data,
	page_walk_rsp,
	l1d_rsp_valid,
	l1i_rsp_valid,
	l1i_gnt,
	l1d_gnt,
	core_mark_dirty_valid,
	core_mark_dirty_addr,
	core_mark_dirty_rsp_valid,
	mem_mark_valid,
	mem_mark_accessed,
	mem_mark_dirty,
	mem_mark_addr,
	mem_mark_rsp_valid,
	mmu_state
);
	reg _sv2v_0;
	input wire clk;
	input wire reset;
	input wire clear_tlb;
	input wire [63:0] page_table_root;
	input wire l1i_req;
	input wire [63:0] l1i_va;
	input wire l1d_req;
	input wire l1d_st;
	input wire [63:0] l1d_va;
	output wire mem_req_valid;
	output wire [31:0] mem_req_addr;
	output wire [63:0] mem_req_data;
	output wire mem_req_store;
	output wire mem_mark_valid;
	output wire mem_mark_accessed;
	output wire mem_mark_dirty;
	output wire [63:0] mem_mark_addr;
	input wire mem_mark_rsp_valid;
	input wire mem_rsp_valid;
	input wire [63:0] mem_rsp_data;
	output reg [71:0] page_walk_rsp;
	output wire l1d_rsp_valid;
	output wire l1i_rsp_valid;
	output wire l1i_gnt;
	output wire l1d_gnt;
	input wire core_mark_dirty_valid;
	input wire [63:0] core_mark_dirty_addr;
	output wire core_mark_dirty_rsp_valid;
	output wire [3:0] mmu_state;
	reg [63:0] n_addr;
	reg [63:0] r_addr;
	reg [63:0] n_last_addr;
	reg [63:0] r_last_addr;
	reg [63:0] n_va;
	reg [63:0] r_va;
	reg [63:0] r_pa;
	reg [63:0] n_pa;
	reg r_req;
	reg n_req;
	reg n_page_fault;
	reg r_page_fault;
	reg n_l1d_rsp_valid;
	reg r_l1d_rsp_valid;
	reg n_l1i_rsp_valid;
	reg r_l1i_rsp_valid;
	reg r_do_l1i;
	reg n_do_l1i;
	reg r_do_l1d;
	reg n_do_l1d;
	reg r_do_dirty;
	reg n_do_dirty;
	reg [1:0] n_hit_lvl;
	reg [1:0] r_hit_lvl;
	reg r_page_dirty;
	reg n_page_dirty;
	reg r_page_read;
	reg n_page_read;
	reg r_page_write;
	reg n_page_write;
	reg r_page_user;
	reg n_page_user;
	reg n_page_executable;
	reg r_page_executable;
	reg r_mem_mark_valid;
	reg n_mem_mark_valid;
	reg r_mem_mark_accessed;
	reg n_mem_mark_accessed;
	reg r_mem_mark_dirty;
	reg n_mem_mark_dirty;
	reg r_core_mark_dirty_rsp_valid;
	reg n_core_mark_dirty_rsp_valid;
	assign mem_req_valid = r_req;
	assign mem_req_addr = r_addr[31:0];
	assign l1d_rsp_valid = r_l1d_rsp_valid;
	assign l1i_rsp_valid = r_l1i_rsp_valid;
	assign mem_mark_addr = r_last_addr;
	assign mem_mark_valid = r_mem_mark_valid;
	assign mem_mark_accessed = r_mem_mark_accessed;
	assign mem_mark_dirty = r_mem_mark_dirty;
	assign core_mark_dirty_rsp_valid = r_core_mark_dirty_rsp_valid;
	always @(*) begin
		if (_sv2v_0)
			;
		page_walk_rsp[65-:64] = r_pa;
		page_walk_rsp[71] = r_page_fault;
		page_walk_rsp[70] = r_page_dirty;
		page_walk_rsp[69] = r_page_read;
		page_walk_rsp[68] = r_page_write;
		page_walk_rsp[67] = r_page_executable;
		page_walk_rsp[66] = r_page_user;
		page_walk_rsp[1-:2] = r_hit_lvl;
	end
	assign mem_req_data = 'd0;
	reg [3:0] r_state;
	reg [3:0] n_state;
	reg n_l1i_req;
	reg r_l1i_req;
	reg n_l1d_req;
	reg r_l1d_req;
	reg n_dirty_req;
	reg r_dirty_req;
	reg n_gnt_l1i;
	reg r_gnt_l1i;
	reg n_gnt_l1d;
	reg r_gnt_l1d;
	assign mmu_state = r_state;
	assign l1i_gnt = r_gnt_l1i;
	assign l1d_gnt = r_gnt_l1d;
	wire w_lo_va = &r_va[63:39] & (r_va[39] == r_va[38]);
	wire w_hi_va = &(~r_va[63:39]) & (r_va[39] == r_va[38]);
	wire w_bad_va = (w_lo_va | w_hi_va) == 1'b0;
	reg [63:0] r_cycle;
	always @(posedge clk) r_cycle <= (reset ? 64'd0 : r_cycle + 64'd1);
	always @(*) begin
		if (_sv2v_0)
			;
		n_l1i_req = r_l1i_req | l1i_req;
		n_l1d_req = r_l1d_req | l1d_req;
		n_dirty_req = r_dirty_req | core_mark_dirty_valid;
		n_l1d_rsp_valid = 1'b0;
		n_l1i_rsp_valid = 1'b0;
		n_addr = r_addr;
		n_last_addr = r_last_addr;
		n_mem_mark_accessed = r_mem_mark_accessed;
		n_mem_mark_valid = 1'b0;
		n_mem_mark_dirty = r_mem_mark_dirty;
		n_req = 1'b0;
		n_va = r_va;
		n_pa = r_pa;
		n_state = r_state;
		n_page_fault = 1'b0;
		n_page_dirty = 1'b0;
		n_page_executable = 1'b0;
		n_page_write = 1'b0;
		n_page_read = 1'b0;
		n_page_user = 1'b0;
		n_do_l1i = r_do_l1i;
		n_do_l1d = r_do_l1d;
		n_do_dirty = r_do_dirty;
		n_hit_lvl = r_hit_lvl;
		n_gnt_l1i = 1'b0;
		n_gnt_l1d = 1'b0;
		n_core_mark_dirty_rsp_valid = 1'b0;
		case (r_state)
			4'd0:
				if (n_l1i_req) begin
					n_state = 4'd1;
					n_va = l1i_va;
					n_l1i_req = 1'b0;
					n_do_l1i = 1'b1;
					n_do_l1d = 1'b0;
					n_do_dirty = 1'b0;
					n_gnt_l1i = 1'b1;
				end
				else if (n_l1d_req) begin
					n_state = 4'd1;
					n_va = l1d_va;
					n_l1d_req = 1'b0;
					n_do_l1i = 1'b0;
					n_do_l1d = 1'b1;
					n_do_dirty = 1'b0;
					n_gnt_l1d = 1'b1;
				end
				else if (n_dirty_req) begin
					n_do_l1i = 1'b0;
					n_do_l1d = 1'b0;
					n_dirty_req = 1'b0;
					n_do_dirty = 1'b1;
					n_state = 4'd1;
					n_va = core_mark_dirty_addr;
				end
			4'd1: begin
				n_addr = page_table_root + {52'd0, r_va[38:30], 3'd0};
				if (w_bad_va) begin
					n_state = 4'd0;
					n_page_fault = 1'b1;
					n_l1i_rsp_valid = r_do_l1i;
					n_l1d_rsp_valid = r_do_l1d;
				end
				else begin
					n_req = 1'b1;
					n_state = 4'd2;
				end
			end
			4'd2:
				if (mem_rsp_valid) begin
					n_addr = mem_rsp_data;
					n_last_addr = r_addr;
					if (mem_rsp_data[0] == 1'b0) begin
						n_state = 4'd0;
						n_page_fault = 1'b1;
						n_l1i_rsp_valid = r_do_l1i;
						n_l1d_rsp_valid = r_do_l1d;
					end
					else if (|mem_rsp_data[3:1]) begin
						n_hit_lvl = 2'd0;
						n_state = 4'd7;
					end
					else
						n_state = 4'd3;
				end
			4'd3: begin
				n_addr = {8'd0, r_addr[53:10], 12'd0} + {52'd0, r_va[29:21], 3'd0};
				n_req = 1'b1;
				n_state = 4'd4;
			end
			4'd4:
				if (mem_rsp_valid) begin
					n_addr = mem_rsp_data;
					n_last_addr = r_addr;
					if (mem_rsp_data[0] == 1'b0) begin
						n_state = 4'd0;
						n_page_fault = 1'b1;
						n_l1i_rsp_valid = r_do_l1i;
						n_l1d_rsp_valid = r_do_l1d;
					end
					else if (|mem_rsp_data[3:1]) begin
						n_hit_lvl = 2'd1;
						n_state = 4'd7;
					end
					else
						n_state = 4'd5;
				end
			4'd5: begin
				n_addr = {8'd0, r_addr[53:10], 12'd0} + {52'd0, r_va[20:12], 3'd0};
				n_req = 1'b1;
				n_state = 4'd6;
			end
			4'd6:
				if (mem_rsp_valid) begin
					n_addr = mem_rsp_data;
					n_last_addr = r_addr;
					if (mem_rsp_data[0] == 1'b0) begin
						n_state = 4'd0;
						n_page_fault = 1'b1;
						n_l1i_rsp_valid = r_do_l1i;
						n_l1d_rsp_valid = r_do_l1d;
					end
					else begin
						n_hit_lvl = 2'd2;
						n_state = 4'd7;
					end
				end
			4'd7: begin
				if (r_hit_lvl == 2'd2)
					n_pa = {8'd0, r_addr[53:10], 12'd0};
				else if (r_hit_lvl == 2'd1)
					n_pa = {8'd0, r_addr[53:19], r_va[20:12], 12'd0};
				else if (r_hit_lvl == 2'd0)
					n_pa = {8'd0, r_addr[53:28], r_va[29:12], 12'd0};
				n_l1i_rsp_valid = r_do_l1i;
				n_l1d_rsp_valid = r_do_l1d;
				n_page_dirty = r_addr[7];
				n_page_read = r_addr[1];
				n_page_write = r_addr[2];
				n_page_executable = r_addr[3];
				n_page_user = r_addr[4];
				if (r_do_dirty) begin
					if (r_addr[7] == 1'b0) begin
						n_mem_mark_valid = 1'b1;
						n_mem_mark_dirty = 1'b1;
						n_state = 4'd8;
					end
					else begin
						n_core_mark_dirty_rsp_valid = 1'b1;
						n_state = 4'd0;
					end
				end
				else if (r_addr[6] == 1'b0) begin
					n_mem_mark_valid = 1'b1;
					n_mem_mark_accessed = 1'b1;
					n_state = 4'd8;
				end
				else
					n_state = 4'd0;
			end
			4'd8:
				if (mem_mark_rsp_valid) begin
					n_state = 4'd0;
					n_core_mark_dirty_rsp_valid = r_do_dirty;
					n_mem_mark_valid = 1'b0;
					n_mem_mark_dirty = 1'b0;
					n_mem_mark_accessed = 1'b0;
				end
			default:
				;
		endcase
	end
	always @(posedge clk)
		if (reset) begin
			r_state <= 4'd0;
			r_addr <= 'd0;
			r_mem_mark_valid <= 1'b0;
			r_mem_mark_accessed <= 1'b0;
			r_mem_mark_dirty <= 1'b0;
			r_last_addr <= 'd0;
			r_req <= 1'b0;
			r_va <= 'd0;
			r_pa <= 'd0;
			r_l1i_req <= 1'b0;
			r_l1d_req <= 1'b0;
			r_dirty_req <= 1'b0;
			r_l1i_rsp_valid <= 1'b0;
			r_l1d_rsp_valid <= 1'b0;
			r_page_fault <= 1'b0;
			r_page_dirty <= 1'b0;
			r_page_executable <= 1'b0;
			r_page_read <= 1'b0;
			r_page_write <= 1'b0;
			r_page_user <= 1'b0;
			r_do_l1i <= 1'b0;
			r_do_l1d <= 1'b0;
			r_do_dirty <= 1'b0;
			r_hit_lvl <= 2'd0;
			r_gnt_l1i <= 1'b0;
			r_gnt_l1d <= 1'b0;
			r_core_mark_dirty_rsp_valid <= 1'b0;
		end
		else begin
			r_state <= n_state;
			r_addr <= n_addr;
			r_mem_mark_valid <= n_mem_mark_valid;
			r_mem_mark_accessed <= n_mem_mark_accessed;
			r_mem_mark_dirty <= n_mem_mark_dirty;
			r_last_addr <= n_last_addr;
			r_req <= n_req;
			r_va <= n_va;
			r_pa <= n_pa;
			r_l1i_req <= n_l1i_req;
			r_l1d_req <= n_l1d_req;
			r_dirty_req <= n_dirty_req;
			r_l1i_rsp_valid <= n_l1i_rsp_valid;
			r_l1d_rsp_valid <= n_l1d_rsp_valid;
			r_page_fault <= n_page_fault;
			r_page_dirty <= n_page_dirty;
			r_page_executable <= n_page_executable;
			r_page_read <= n_page_read;
			r_page_write <= n_page_write;
			r_page_user <= n_page_user;
			r_do_l1i <= n_do_l1i;
			r_do_l1d <= n_do_l1d;
			r_do_dirty <= n_do_dirty;
			r_hit_lvl <= n_hit_lvl;
			r_gnt_l1i <= n_gnt_l1i;
			r_gnt_l1d <= n_gnt_l1d;
			r_core_mark_dirty_rsp_valid <= n_core_mark_dirty_rsp_valid;
		end
	initial _sv2v_0 = 0;
endmodule

module dffen (
	q,
	d,
	clk,
	reset,
	en
);
	parameter N = 1;
	input wire [N - 1:0] d;
	input wire clk;
	input wire reset;
	input wire en;
	output reg [N - 1:0] q;
	always @(posedge clk)
		if (reset)
			q <= 1'b0;
		else
			q <= (en ? d : q);
endmodule
module shiftregbit (
	clk,
	reset,
	clear,
	b,
	valid,
	out
);
	input wire clk;
	input wire reset;
	input wire clear;
	input wire b;
	input wire valid;
	parameter W = 32;
	output wire [W - 1:0] out;
	genvar _gv_i_1;
	generate
		for (_gv_i_1 = 0; _gv_i_1 < W; _gv_i_1 = _gv_i_1 + 1) begin : sr
			localparam i = _gv_i_1;
			if (i == 0) begin : genblk1
				dffen #(.N(1)) ff(
					.clk(clk),
					.reset(reset | clear),
					.en(valid),
					.d(b),
					.q(out[0])
				);
			end
			else begin : genblk1
				dffen #(.N(1)) ff(
					.clk(clk),
					.reset(reset | clear),
					.en(valid),
					.d(out[i - 1]),
					.q(out[i])
				);
			end
		end
	endgenerate
endmodule

module divider (
	clk,
	reset,
	flush,
	wb_slot_used,
	inA,
	inB,
	rob_ptr_in,
	prf_ptr_in,
	is_signed_div,
	is_rem,
	is_w,
	start_div,
	y,
	rob_ptr_out,
	prf_ptr_out,
	ready,
	complete
);
	reg _sv2v_0;
	parameter LG_W = 5;
	localparam W = 1 << LG_W;
	localparam W2 = 2 * W;
	input wire clk;
	input wire reset;
	input wire flush;
	input wire wb_slot_used;
	input wire [63:0] inA;
	input wire [63:0] inB;
	input wire [4:0] rob_ptr_in;
	input wire [6:0] prf_ptr_in;
	input wire is_signed_div;
	input wire is_rem;
	input wire is_w;
	input wire start_div;
	output reg [63:0] y;
	output reg [4:0] rob_ptr_out;
	output reg [6:0] prf_ptr_out;
	output reg ready;
	output reg complete;
	reg [2:0] r_state;
	reg [2:0] n_state;
	reg r_is_signed;
	reg n_is_signed;
	reg r_sign;
	reg n_sign;
	reg r_rem_sign;
	reg n_rem_sign;
	reg r_is_rem_op;
	reg n_is_rem_op;
	reg [4:0] r_rob_ptr;
	reg [4:0] n_rob_ptr;
	reg [6:0] r_gpr_prf_ptr;
	reg [6:0] n_gpr_prf_ptr;
	reg [W - 1:0] r_A;
	reg [W - 1:0] n_A;
	reg [W - 1:0] r_B;
	reg [W - 1:0] n_B;
	reg [W - 1:0] r_lastA;
	reg [W - 1:0] n_lastA;
	reg [W - 1:0] r_lastB;
	reg [W - 1:0] n_lastB;
	reg r_last_signed;
	reg n_last_signed;
	reg [W - 1:0] r_last_ss;
	reg [W - 1:0] n_last_ss;
	reg [W2 - 1:0] r_last_Y;
	reg [W2 - 1:0] n_last_Y;
	reg [W2 - 1:0] r_last_R;
	reg [W2 - 1:0] n_last_R;
	reg r_last_valid;
	reg n_last_valid;
	reg [W2 - 1:0] r_Y;
	reg [W2 - 1:0] n_Y;
	reg [W2 - 1:0] r_D;
	reg [W2 - 1:0] n_D;
	reg [W2 - 1:0] r_R;
	reg [W2 - 1:0] n_R;
	reg [W - 1:0] t_ss;
	reg r_is_w;
	reg n_is_w;
	reg [LG_W:0] r_idx;
	reg [LG_W:0] n_idx;
	reg t_bit;
	reg t_valid;
	reg t_clr;
	wire [W - 1:0] srcA = inA[W - 1:0];
	wire [W - 1:0] srcB = inB[W - 1:0];
	always @(posedge clk)
		if (reset) begin
			r_state <= 3'd0;
			r_rob_ptr <= 'd0;
			r_gpr_prf_ptr <= 'd0;
			r_is_signed <= 1'b0;
			r_sign <= 1'b0;
			r_rem_sign <= 1'b0;
			r_is_rem_op <= 1'b0;
			r_A <= 'd0;
			r_B <= 'd0;
			r_Y <= 'd0;
			r_D <= 'd0;
			r_R <= 'd0;
			r_lastA <= 64'd0;
			r_lastB <= 64'd0;
			r_last_Y <= 'd0;
			r_last_R <= 'd0;
			r_last_ss <= 'd0;
			r_last_signed <= 1'b0;
			r_last_valid <= 1'b0;
			r_idx <= 'd0;
			r_is_w <= 1'b0;
		end
		else begin
			r_state <= n_state;
			r_rob_ptr <= n_rob_ptr;
			r_gpr_prf_ptr <= n_gpr_prf_ptr;
			r_is_signed <= n_is_signed;
			r_sign <= n_sign;
			r_rem_sign <= n_rem_sign;
			r_is_rem_op <= n_is_rem_op;
			r_A <= n_A;
			r_B <= n_B;
			r_Y <= n_Y;
			r_D <= n_D;
			r_R <= n_R;
			r_lastA <= n_lastA;
			r_lastB <= n_lastB;
			r_last_Y <= n_last_Y;
			r_last_R <= n_last_R;
			r_last_ss <= n_last_ss;
			r_last_signed <= n_last_signed;
			r_last_valid <= n_last_valid;
			r_idx <= n_idx;
			r_is_w <= n_is_w;
		end
	always @(posedge clk)
		if (reset | t_clr)
			t_ss <= 'd0;
		else if (t_valid)
			t_ss <= t_ss | ({{W - 1 {1'b0}}, t_bit} << r_idx);
	wire w_match_prev = (((r_lastA == r_A) & (r_lastB == r_B)) & (r_last_signed == r_is_signed)) & r_last_valid;
	wire [LG_W:0] w_clz_A;
	count_leading_zeros #(.LG_N(LG_W)) clz0(
		.in(r_A),
		.y(w_clz_A)
	);
	always @(*) begin
		if (_sv2v_0)
			;
		n_rob_ptr = r_rob_ptr;
		n_gpr_prf_ptr = r_gpr_prf_ptr;
		n_state = r_state;
		n_is_signed = r_is_signed;
		n_sign = r_sign;
		n_rem_sign = r_rem_sign;
		n_is_rem_op = r_is_rem_op;
		n_A = r_A;
		n_B = r_B;
		n_Y = r_Y;
		n_D = r_D;
		n_R = r_R;
		n_lastA = r_lastA;
		n_lastB = r_lastB;
		n_last_signed = r_last_signed;
		n_last_Y = r_last_Y;
		n_last_R = r_last_R;
		n_last_ss = r_last_ss;
		n_last_valid = r_last_valid;
		n_idx = r_idx;
		t_bit = 1'b0;
		t_clr = 1'b0;
		t_valid = 1'b0;
		n_is_w = r_is_w;
		ready = (r_state == 3'd0) & !start_div;
		rob_ptr_out = r_rob_ptr;
		prf_ptr_out = r_gpr_prf_ptr;
		y = r_Y[W - 1:0];
		complete = 1'b0;
		(* full_case, parallel_case *)
		case (r_state)
			3'd0: begin
				t_clr = 1'b1;
				n_is_w = is_w;
				n_rob_ptr = rob_ptr_in;
				n_gpr_prf_ptr = prf_ptr_in;
				n_is_rem_op = is_rem;
				n_is_signed = is_signed_div;
				n_state = (start_div ? 3'd2 : 3'd0);
				n_idx = W - 1;
				n_sign = srcA[W - 1] ^ srcB[W - 1];
				n_rem_sign = srcA[W - 1];
				n_A = (is_signed_div & srcA[W - 1] ? ~srcA + 'd1 : srcA);
				n_B = (is_signed_div & srcB[W - 1] ? ~srcB + 'd1 : srcB);
				n_D = {n_B, {W {1'b0}}};
				n_R = {{W {1'b0}}, n_A};
			end
			3'd2: begin
				n_state = 3'd1;
				n_idx = 7'd63 - w_clz_A;
				n_R = r_R << w_clz_A;
			end
			3'd1: begin
				if ({r_R[W2 - 2:0], 1'b0} >= r_D) begin
					n_R = {r_R[W2 - 2:0], 1'b0} - r_D;
					t_bit = 1'b1;
					t_valid = 1'b1;
				end
				else begin
					n_R = {r_R[W2 - 2:0], 1'b0};
					t_bit = 1'b0;
					t_valid = 1'b1;
				end
				n_state = (w_match_prev | flush ? 3'd5 : (r_idx == 'd0 ? 3'd3 : 3'd1));
				n_idx = r_idx - 'd1;
			end
			3'd3: begin
				n_state = 3'd6;
				n_lastA = r_A;
				n_lastB = r_B;
				n_last_signed = r_is_signed;
				n_last_valid = 1'b1;
				n_Y[W - 1:0] = t_ss;
				n_Y[W2 - 1:W] = n_R[W2 - 1:W];
				n_last_Y = n_Y;
				n_last_R = n_R;
				n_last_ss = t_ss;
				if (r_is_signed && r_sign)
					n_Y[W - 1:0] = ~t_ss + 'd1;
				if (r_is_signed && r_rem_sign)
					n_Y[W2 - 1:W] = ~n_R[W2 - 1:W] + 'd1;
				if (r_is_rem_op)
					n_Y[W - 1:0] = n_Y[W2 - 1:W];
				if (r_is_w)
					n_Y = {{96 {n_Y[31]}}, n_Y[31:0]};
			end
			3'd4: begin
				complete = 1'b1;
				n_state = 3'd0;
			end
			3'd5: begin
				n_Y = r_last_Y;
				n_R = r_last_R;
				if (r_is_signed && r_sign)
					n_Y[W - 1:0] = ~r_last_ss + 'd1;
				if (r_is_signed && r_rem_sign)
					n_Y[W2 - 1:W] = ~n_R[W2 - 1:W] + 'd1;
				if (r_is_rem_op)
					n_Y[W - 1:0] = n_Y[W2 - 1:W];
				if (r_is_w)
					n_Y = {{96 {n_Y[31]}}, n_Y[31:0]};
				n_state = 3'd6;
			end
			3'd6:
				if (wb_slot_used == 1'b0) begin
					n_state = 3'd0;
					complete = 1'b1;
				end
			default:
				;
		endcase
	end
	initial _sv2v_0 = 0;
endmodule

module nu_l1d (
	clk,
	reset,
	l2_empty,
	priv,
	page_table_root,
	l2_probe_addr,
	l2_probe_val,
	l2_probe_ack,
	l1d_state,
	restart_complete,
	paging_active,
	clear_tlb,
	page_walk_req_valid,
	page_walk_req_va,
	page_walk_rsp_gnt,
	page_walk_rsp_valid,
	page_walk_rsp,
	head_of_rob_ptr,
	head_of_rob_ptr_valid,
	retired_rob_ptr_valid,
	retired_rob_ptr_two_valid,
	retired_rob_ptr,
	retired_rob_ptr_two,
	memq_empty,
	drain_ds_complete,
	dead_rob_mask,
	flush_req,
	flush_complete,
	flush_cl_req,
	flush_cl_addr,
	core_mem_va_req_valid,
	core_mem_va_req,
	core_store_data_valid,
	core_store_data,
	core_store_data_ack,
	core_mem_va_req_ack,
	core_mem_rsp,
	core_mem_rsp_valid,
	mem_rdy,
	mem_req_valid,
	mem_req,
	l2_rsp_valid,
	l2_rsp_load_data,
	l2_rsp_tag,
	l2_rsp_writeback,
	l2_rsp_addr,
	mtimecmp,
	mtimecmp_val,
	cache_accesses,
	cache_hits,
	tlb_accesses,
	tlb_hits
);
	reg _sv2v_0;
	localparam L1D_NUM_SETS = 256;
	localparam L1D_CL_LEN = 16;
	localparam L1D_CL_LEN_BITS = 128;
	input wire clk;
	input wire reset;
	input wire l2_empty;
	input wire [1:0] priv;
	input wire [63:0] page_table_root;
	input wire l2_probe_val;
	input wire [31:0] l2_probe_addr;
	output wire l2_probe_ack;
	output wire [3:0] l1d_state;
	input wire restart_complete;
	input wire paging_active;
	input wire clear_tlb;
	output wire page_walk_req_valid;
	output wire [63:0] page_walk_req_va;
	input wire page_walk_rsp_gnt;
	input wire page_walk_rsp_valid;
	input wire [71:0] page_walk_rsp;
	input wire [4:0] head_of_rob_ptr;
	input wire head_of_rob_ptr_valid;
	input wire retired_rob_ptr_valid;
	input wire retired_rob_ptr_two_valid;
	input wire [4:0] retired_rob_ptr;
	input wire [4:0] retired_rob_ptr_two;
	output reg memq_empty;
	input wire drain_ds_complete;
	input wire [31:0] dead_rob_mask;
	input wire flush_cl_req;
	input wire [63:0] flush_cl_addr;
	input wire flush_req;
	output wire flush_complete;
	input wire core_mem_va_req_valid;
	input wire [230:0] core_mem_va_req;
	input wire core_store_data_valid;
	input wire [68:0] core_store_data;
	output reg core_store_data_ack;
	output reg core_mem_va_req_ack;
	output wire [147:0] core_mem_rsp;
	output wire core_mem_rsp_valid;
	input wire mem_rdy;
	output wire mem_req_valid;
	output reg [168:0] mem_req;
	input wire l2_rsp_valid;
	input wire [127:0] l2_rsp_load_data;
	input wire [3:0] l2_rsp_tag;
	input wire [31:0] l2_rsp_addr;
	input wire l2_rsp_writeback;
	output wire [63:0] mtimecmp;
	output wire mtimecmp_val;
	output wire [63:0] cache_accesses;
	output wire [63:0] cache_hits;
	output wire [63:0] tlb_accesses;
	output wire [63:0] tlb_hits;
	localparam LG_WORDS_PER_CL = 2;
	localparam LG_DWORDS_PER_CL = 1;
	localparam WORDS_PER_CL = 4;
	localparam BYTES_PER_CL = 16;
	localparam N_TAG_BITS = 20;
	localparam IDX_START = 4;
	localparam IDX_STOP = 12;
	localparam WORD_START = 2;
	localparam WORD_STOP = 4;
	localparam DWORD_START = 3;
	localparam DWORD_STOP = 4;
	localparam N_MQ_ENTRIES = 8;
	reg r_got_req;
	reg r_last_wr;
	reg n_last_wr;
	reg r_wr_array;
	reg r_got_req2;
	reg r_last_wr2;
	reg n_last_wr2;
	reg rr_got_req;
	reg rr_last_wr;
	reg rr_is_retry;
	reg rr_did_reload;
	reg r_lock_cache;
	reg n_lock_cache;
	reg n_l2_probe_ack;
	reg r_l2_probe_ack;
	assign l2_probe_ack = r_l2_probe_ack;
	reg [3:0] r_n_inflight;
	reg [7:0] t_cache_idx;
	reg [7:0] r_cache_idx;
	reg [7:0] rr_cache_idx;
	reg [19:0] t_cache_tag;
	reg [19:0] r_cache_tag;
	wire [19:0] r_tag_out;
	reg [19:0] rr_cache_tag;
	wire r_valid_out;
	wire r_dirty_out;
	wire [127:0] r_array_out;
	reg [127:0] t_data;
	reg [127:0] t_data2;
	reg [7:0] t_cache_idx2;
	reg [7:0] r_cache_idx2;
	reg [7:0] rr_cache_idx2;
	reg [19:0] t_cache_tag2;
	reg [19:0] r_cache_tag2;
	wire [19:0] r_tag_out2;
	wire r_valid_out2;
	wire r_dirty_out2;
	wire [127:0] r_array_out2;
	reg [7:0] t_miss_idx;
	reg [7:0] r_miss_idx;
	reg [63:0] t_miss_addr;
	reg [63:0] r_miss_addr;
	reg [7:0] t_array_wr_addr;
	reg [127:0] t_array_wr_data;
	reg [127:0] r_array_wr_data;
	reg t_array_wr_en;
	reg r_flush_req;
	reg n_flush_req;
	reg r_flush_cl_req;
	reg n_flush_cl_req;
	reg r_flush_complete;
	reg n_flush_complete;
	reg [127:0] t_shift;
	reg [127:0] t_shift_2;
	reg [127:0] t_store_shift;
	reg [127:0] t_store_mask;
	reg t_got_rd_retry;
	reg t_port2_hit_cache;
	reg t_mark_invalid;
	reg t_wr_array;
	reg t_wr_store;
	reg t_hit_cache;
	reg t_rsp_dst_valid;
	reg [63:0] t_rsp_data;
	reg t_hit_cache2;
	reg t_rsp_dst_valid2;
	reg [63:0] t_rsp_data2;
	reg [127:0] t_array_data;
	reg [63:0] t_addr;
	reg t_got_req;
	reg t_got_req2;
	reg t_replay_req2;
	reg t_tlb_xlat;
	reg t_tlb_xlat_replay;
	reg n_pending_tlb_miss;
	reg r_pending_tlb_miss;
	reg n_pending_tlb_zero_page;
	reg r_pending_tlb_zero_page;
	reg t_got_miss;
	reg t_dirty_miss;
	reg t_pop_eb;
	reg t_push_eb;
	reg t_push_miss;
	reg t_mh_block;
	reg t_cm_block;
	wire t_cm_block2;
	reg t_cm_block_stall;
	reg r_must_forward;
	reg r_must_forward2;
	reg n_inhibit_write;
	reg r_inhibit_write;
	reg t_got_non_mem;
	reg r_got_non_mem;
	reg t_incr_busy;
	reg t_force_clear_busy;
	reg n_stall_store;
	reg r_stall_store;
	reg n_is_retry;
	reg r_is_retry;
	reg r_q_priority;
	reg n_q_priority;
	reg n_core_mem_rsp_valid;
	reg r_core_mem_rsp_valid;
	localparam N_EB_ENTRIES = 2;
	reg [319:0] r_sb;
	reg [1:0] r_eb_head_ptr;
	reg [1:0] n_eb_head_ptr;
	reg [1:0] r_eb_tail_ptr;
	reg [1:0] n_eb_tail_ptr;
	reg [1:0] r_eb_valid;
	reg [147:0] n_core_mem_rsp;
	reg [147:0] r_core_mem_rsp;
	reg [230:0] n_req;
	reg [230:0] r_req;
	wire [230:0] t_req;
	reg [230:0] n_req2;
	reg [230:0] r_req2;
	reg [230:0] t_req2_pa;
	reg [230:0] r_mem_q [7:0];
	reg [3:0] r_mq_head_ptr;
	reg [3:0] n_mq_head_ptr;
	reg [3:0] r_mq_tail_ptr;
	reg [3:0] n_mq_tail_ptr;
	reg [3:0] t_mq_tail_ptr_plus_one;
	reg [164:0] r_l2q [7:0];
	reg [3:0] r_l2q_head_ptr;
	reg [3:0] n_l2q_head_ptr;
	reg [3:0] r_l2q_tail_ptr;
	reg [3:0] n_l2q_tail_ptr;
	wire w_l2q_empty = r_l2q_tail_ptr == r_l2q_head_ptr;
	always @(posedge clk)
		if (reset) begin
			r_l2q_head_ptr <= 'd0;
			r_l2q_tail_ptr <= 'd0;
			r_eb_head_ptr <= 'd0;
			r_eb_tail_ptr <= 'd0;
		end
		else begin
			r_l2q_head_ptr <= n_l2q_head_ptr;
			r_l2q_tail_ptr <= n_l2q_tail_ptr;
			r_eb_head_ptr <= n_eb_head_ptr;
			r_eb_tail_ptr <= n_eb_tail_ptr;
		end
	wire w_eb_empty = r_eb_head_ptr == r_eb_tail_ptr;
	wire w_eb_full = (r_eb_head_ptr != r_eb_tail_ptr) & (r_eb_head_ptr[0:0] == r_eb_tail_ptr[0:0]);
	wire mem_rsp_valid = (r_got_req & r_req[166] ? 1'b0 : !w_l2q_empty);
	always @(posedge clk)
		if (reset)
			r_eb_valid <= 'd0;
		else begin
			if (t_push_eb)
				r_eb_valid[r_eb_tail_ptr[0:0]] <= 1'b1;
			if (t_pop_eb)
				r_eb_valid[r_eb_head_ptr[0:0]] <= 1'b0;
		end
	reg [31:0] n_port1_req_addr;
	always @(posedge clk)
		if (t_push_eb) begin
			r_sb[(r_eb_tail_ptr[0:0] * 160) + 127-:128] <= t_data;
			r_sb[(r_eb_tail_ptr[0:0] * 160) + 159-:32] <= n_port1_req_addr;
		end
	wire [1:0] w_eb_port1_hits;
	wire [1:0] w_eb_port2_hits;
	genvar _gv_i_1;
	reg [230:0] t_mem_head;
	generate
		for (_gv_i_1 = 0; _gv_i_1 < N_EB_ENTRIES; _gv_i_1 = _gv_i_1 + 1) begin : genblk1
			localparam i = _gv_i_1;
			assign w_eb_port1_hits[i] = (r_eb_valid[i] ? r_sb[(i * 160) + 159-:28] == t_mem_head[198:171] : 1'b0);
			assign w_eb_port2_hits[i] = (r_eb_valid[i] ? r_sb[(i * 160) + 139-:8] == t_cache_idx2 : 1'b0);
		end
	endgenerate
	wire w_eb_port1_hit = |w_eb_port1_hits;
	wire w_eb_port2_hit = |w_eb_port2_hits;
	always @(*) begin
		if (_sv2v_0)
			;
		n_l2q_head_ptr = r_l2q_head_ptr;
		n_l2q_tail_ptr = r_l2q_tail_ptr;
		if (l2_rsp_valid)
			n_l2q_tail_ptr = r_l2q_tail_ptr + 'd1;
		if (mem_rsp_valid)
			n_l2q_head_ptr = r_l2q_head_ptr + 'd1;
	end
	always @(posedge clk)
		if (l2_rsp_valid) begin
			r_l2q[r_l2q_tail_ptr[2:0]][164-:32] <= l2_rsp_addr;
			r_l2q[r_l2q_tail_ptr[2:0]][132-:128] <= l2_rsp_load_data;
			r_l2q[r_l2q_tail_ptr[2:0]][4-:4] <= l2_rsp_tag;
			r_l2q[r_l2q_tail_ptr[2:0]][0] <= l2_rsp_writeback;
		end
	wire [127:0] mem_rsp_load_data = r_l2q[r_l2q_head_ptr[2:0]][132-:128];
	wire [3:0] mem_rsp_tag = r_l2q[r_l2q_head_ptr[2:0]][4-:4];
	wire [31:0] mem_rsp_addr = r_l2q[r_l2q_head_ptr[2:0]][164-:32];
	wire mem_rsp_reload = mem_rsp_valid & (r_l2q[r_l2q_head_ptr[2:0]][0] == 1'b0);
	function [15:0] make_mask;
		input reg [230:0] r;
		reg [15:0] t_m;
		reg [15:0] m;
		reg b;
		reg s;
		reg w;
		reg d;
		begin
			b = ((r[162-:4] == 4'd5) || (r[162-:4] == 4'd0)) || (r[162-:4] == 4'd1);
			s = ((r[162-:4] == 4'd6) || (r[162-:4] == 4'd2)) || (r[162-:4] == 4'd3);
			w = (r[162-:4] == 4'd7) || (r[162-:4] == 4'd4);
			d = (r[162-:4] == 4'd13) || (r[162-:4] == 4'd12);
			t_m = (b ? 16'h0001 : (s ? 16'h0003 : (w ? 16'h000f : (d ? 16'h00ff : 16'hffff))));
			m = t_m << r[170:167];
			make_mask = m;
		end
	endfunction
	reg [15:0] t_mq_mask;
	reg [15:0] t_req_mask;
	always @(*) begin
		if (_sv2v_0)
			;
		t_mq_mask = make_mask(r_req2);
		t_req_mask = make_mask(core_mem_va_req);
	end
	reg [7:0] r_mq_addr_valid;
	reg [7:0] r_mq_inflight;
	reg [7:0] r_last_early;
	reg r_last_early_valid;
	reg [7:0] r_mq_addr [7:0];
	reg [31:0] r_mq_dbg_addr [7:0];
	reg [15:0] r_mq_mask [7:0];
	reg [63:0] r_mq_full_addr [7:0];
	reg r_mq_is_load [7:0];
	reg r_mq_is_unaligned [7:0];
	reg [3:0] r_mq_op [7:0];
	reg [61:0] r_mq_word_addr [7:0];
	wire [15:0] w_store_byte_en;
	wire [230:0] t_mem_tail;
	reg mem_q_full;
	reg mem_q_empty;
	reg mem_q_almost_full;
	reg [3:0] r_state;
	reg [3:0] n_state;
	assign l1d_state = r_state;
	reg t_pop_mq;
	reg n_did_reload;
	reg r_did_reload;
	reg r_got_rd_retry;
	reg r_mem_req_valid;
	reg n_mem_req_valid;
	reg r_mem_req_uc;
	reg n_mem_req_uc;
	reg [31:0] r_mem_req_addr;
	reg [31:0] n_mem_req_addr;
	reg [127:0] r_mem_req_store_data;
	reg [127:0] n_mem_req_store_data;
	reg [3:0] r_mem_req_opcode;
	reg [3:0] n_mem_req_opcode;
	reg [3:0] r_mem_req_tag;
	reg [3:0] n_mem_req_tag;
	reg n_port1_req_valid;
	reg n_port1_req_uc;
	reg [127:0] n_port1_req_store_data;
	reg [3:0] n_port1_req_opcode;
	reg [3:0] n_port1_req_tag;
	reg n_port2_req_valid;
	reg n_port2_req_uc;
	reg [31:0] n_port2_req_addr;
	reg [127:0] n_port2_req_store_data;
	reg [3:0] n_port2_req_opcode;
	reg [3:0] n_port2_req_tag;
	reg [63:0] r_cache_accesses;
	reg [63:0] r_cache_hits;
	reg [63:0] n_cache_accesses;
	reg [63:0] n_cache_hits;
	wire w_tlb_hit;
	wire w_tlb_dirty;
	wire w_tlb_writable;
	wire w_tlb_readable;
	wire w_tlb_user;
	wire w_zero_page;
	wire [31:0] w_tlb_pa;
	reg [63:0] r_tlb_addr;
	reg [63:0] n_tlb_addr;
	reg t_reload_tlb;
	reg n_page_walk_req_valid;
	reg r_page_walk_req_valid;
	reg r_page_walk_gnt;
	reg n_page_walk_gnt;
	reg n_flush_was_active;
	reg r_flush_was_active;
	reg [63:0] r_store_stalls;
	reg [63:0] n_store_stalls;
	reg [63:0] r_cycle;
	assign flush_complete = r_flush_complete;
	assign mem_req_valid = r_mem_req_valid;
	always @(*) begin
		if (_sv2v_0)
			;
		mem_req[167-:32] = r_mem_req_addr[31:0];
		mem_req[131-:128] = r_mem_req_store_data;
		mem_req[3-:4] = r_mem_req_opcode;
		mem_req[135-:4] = r_mem_req_tag;
		mem_req[168] = r_mem_req_uc;
	end
	assign core_mem_rsp_valid = n_core_mem_rsp_valid;
	assign core_mem_rsp = n_core_mem_rsp;
	assign cache_accesses = r_cache_accesses;
	assign cache_hits = r_cache_hits;
	assign page_walk_req_valid = r_page_walk_req_valid;
	assign page_walk_req_va = r_tlb_addr;
	always @(posedge clk) r_cycle <= (reset ? 'd0 : r_cycle + 'd1);
	always @(posedge clk)
		if (reset) begin
			r_mq_head_ptr <= 'd0;
			r_mq_tail_ptr <= 'd0;
		end
		else begin
			r_mq_head_ptr <= n_mq_head_ptr;
			r_mq_tail_ptr <= n_mq_tail_ptr;
		end
	localparam N_ROB_ENTRIES = 32;
	reg [1:0] r_graduated [31:0];
	reg [31:0] r_rob_inflight;
	reg t_reset_graduated;
	always @(posedge clk)
		if (r_state == 4'd1)
			r_graduated[r_cache_idx[4:0]] <= 2'b00;
		else begin
			if (retired_rob_ptr_valid && (r_graduated[retired_rob_ptr] == 2'b01))
				r_graduated[retired_rob_ptr] <= 2'b10;
			if (retired_rob_ptr_two_valid && (r_graduated[retired_rob_ptr_two] == 2'b01))
				r_graduated[retired_rob_ptr_two] <= 2'b10;
			if (t_incr_busy)
				r_graduated[r_req2[144-:5]] <= 2'b01;
			if (t_reset_graduated)
				r_graduated[r_req[144-:5]] <= 2'b00;
			if (t_force_clear_busy)
				r_graduated[t_mem_head[144-:5]] <= 2'b00;
		end
	always @(posedge clk)
		if (reset)
			r_n_inflight <= 'd0;
		else if ((core_mem_va_req_valid && core_mem_va_req_ack) && !core_mem_rsp_valid)
			r_n_inflight <= r_n_inflight + 'd1;
		else if (!(core_mem_va_req_valid && core_mem_va_req_ack) && core_mem_rsp_valid)
			r_n_inflight <= r_n_inflight - 'd1;
	always @(*) begin
		if (_sv2v_0)
			;
		n_mq_head_ptr = r_mq_head_ptr;
		n_mq_tail_ptr = r_mq_tail_ptr;
		t_mq_tail_ptr_plus_one = r_mq_tail_ptr + 'd1;
		if (t_push_miss)
			n_mq_tail_ptr = r_mq_tail_ptr + 'd1;
		if (t_pop_mq)
			n_mq_head_ptr = r_mq_head_ptr + 'd1;
		t_mem_head = r_mem_q[r_mq_head_ptr[2:0]];
		mem_q_empty = r_mq_head_ptr == r_mq_tail_ptr;
		mem_q_full = (r_mq_head_ptr != r_mq_tail_ptr) & (r_mq_head_ptr[2:0] == r_mq_tail_ptr[2:0]);
		mem_q_almost_full = (r_mq_head_ptr != t_mq_tail_ptr_plus_one) & (r_mq_head_ptr[2:0] == t_mq_tail_ptr_plus_one[2:0]);
	end
	always @(posedge clk)
		if (reset)
			r_rob_inflight <= 'd0;
		else begin
			if ((r_got_req2 && !drain_ds_complete) && t_push_miss) begin
				if (r_rob_inflight[r_req2[144-:5]] == 1'b1)
					$display("entry %d should not be inflight\n", r_req2[144-:5]);
				r_rob_inflight[r_req2[144-:5]] <= 1'b1;
			end
			if ((r_got_req && r_valid_out) && (r_tag_out == r_cache_tag)) begin
				if (r_rob_inflight[r_req[144-:5]] == 1'b0)
					$display("huh %d should be inflight....\n", r_req[144-:5]);
				r_rob_inflight[r_req[144-:5]] <= 1'b0;
			end
			if (t_force_clear_busy)
				r_rob_inflight[t_mem_head[144-:5]] <= 1'b0;
		end
	wire w_cache_port1_hit = r_valid_out & (r_tag_out == r_cache_tag);
	wire w_cache_port1_clean_miss = !r_valid_out;
	wire w_req_port_free = (r_got_req ? w_cache_port1_hit : 1'b1);
	wire w_port2_dirty_miss = (r_valid_out2 && r_dirty_out2) && (r_tag_out2 != w_tlb_pa[31:IDX_STOP]);
	wire w_port2_hit_cache = r_valid_out2 && (r_tag_out2 == w_tlb_pa[31:IDX_STOP]);
	reg r_pop_busy_addr2;
	wire w_hit_pop = (r_pop_busy_addr2 ? r_cache_idx == r_req2[178:171] : 1'b0);
	reg [2:0] r_mrq_credits;
	reg [2:0] n_mrq_credits;
	always @(posedge clk) r_mrq_credits <= (reset ? {3 {1'b1}} : n_mrq_credits);
	wire w_one_free_credit = r_mrq_credits != 'd0;
	wire w_two_free_credits = r_mrq_credits > 'd1;
	wire w_three_free_credits = r_mrq_credits > 'd2;
	wire w_queues_drained = &r_mrq_credits & w_eb_empty;
	reg r_fwd_busy_addr2;
	reg r_hit_busy_line2;
	wire w_could_early_req_any = ((((((((t_push_miss & w_three_free_credits) & !t_port2_hit_cache) & (r_last_early_valid ? r_last_early != r_req2[178:171] : 1'b1)) & !((r_hit_busy_line2 | r_fwd_busy_addr2) | w_hit_pop)) & (r_req2[165] | r_req[166])) & w_tlb_hit) & (rr_last_wr ? rr_cache_idx != r_req2[178:171] : 1'b1)) & (r_last_wr ? r_cache_idx != r_req2[178:171] : 1'b1)) & (n_last_wr ? t_cache_idx != r_req2[178:171] : 1'b1);
	wire w_could_early_req = !w_port2_dirty_miss & w_could_early_req_any;
	wire w_gen_early_req = w_could_early_req & (r_got_req ? w_cache_port1_hit : 1'b1);
	wire w_early_rsp = (mem_rsp_valid ? mem_rsp_tag != 8 : 1'b0);
	always @(posedge clk) begin
		r_last_early_valid <= (reset ? 1'b0 : w_gen_early_req);
		r_last_early <= r_req2[178:171];
	end
	always @(posedge clk)
		if (reset)
			r_mq_inflight <= 'd0;
		else begin
			if (w_gen_early_req)
				r_mq_inflight[r_mq_tail_ptr[2:0]] <= 1'b1;
			if (w_early_rsp & (mem_rsp_tag[3] == 1'b0))
				r_mq_inflight[mem_rsp_tag[2:0]] <= 1'b0;
		end
	always @(*) begin
		if (_sv2v_0)
			;
		n_port2_req_valid = w_gen_early_req;
		n_port2_req_uc = 1'b0;
		n_port2_req_addr = w_tlb_pa[31:0];
		n_port2_req_store_data = r_mem_req_store_data;
		n_port2_req_opcode = 4'd4;
		n_port2_req_tag = {1'b0, r_mq_tail_ptr[2:0]};
	end
	always @(posedge clk)
		if (t_push_miss) begin
			r_mem_q[r_mq_tail_ptr[2:0]] <= t_req2_pa;
			r_mq_addr[r_mq_tail_ptr[2:0]] <= r_req2[178:171];
			r_mq_dbg_addr[r_mq_tail_ptr[2:0]] <= w_tlb_pa[31:0];
			r_mq_mask[r_mq_tail_ptr[2:0]] <= t_mq_mask & {16 {r_req2[166]}};
			r_mq_op[r_mq_tail_ptr[2:0]] <= r_req2[162-:4];
			r_mq_is_load[r_mq_tail_ptr[2:0]] <= r_req2[165];
			r_mq_is_unaligned[r_mq_tail_ptr[2:0]] <= r_req2[152];
			r_mq_full_addr[r_mq_tail_ptr[2:0]] <= r_req2[230-:64];
			r_mq_word_addr[r_mq_tail_ptr[2:0]] <= r_req2[230:169];
		end
	always @(posedge clk)
		if (reset)
			r_mq_addr_valid <= 'd0;
		else begin
			if (t_push_miss)
				r_mq_addr_valid[r_mq_tail_ptr[2:0]] <= 1'b1;
			if (t_pop_mq)
				r_mq_addr_valid[r_mq_head_ptr[2:0]] <= 1'b0;
		end
	wire [7:0] w_hit_busy_addrs;
	reg [7:0] r_hit_busy_addrs;
	reg r_hit_busy_addr;
	wire [7:0] w_hit_busy_addrs2;
	wire [7:0] w_hit_busy_line2;
	wire [7:0] w_addr_intersect;
	reg [7:0] r_hit_busy_addrs2;
	reg r_hit_busy_addr2;
	wire [7:0] w_unaligned_in_mq;
	reg r_any_unaligned;
	genvar _gv_i_2;
	generate
		for (_gv_i_2 = 0; _gv_i_2 < N_MQ_ENTRIES; _gv_i_2 = _gv_i_2 + 1) begin : genblk2
			localparam i = _gv_i_2;
			assign w_hit_busy_addrs[i] = (t_pop_mq && (r_mq_head_ptr[2:0] == i) ? 1'b0 : (r_mq_addr_valid[i] ? r_mq_addr[i] == t_cache_idx : 1'b0));
			assign w_addr_intersect[i] = |(r_mq_mask[i] & t_req_mask);
			assign w_hit_busy_line2[i] = (r_mq_addr_valid[i] ? r_mq_addr[i] == t_cache_idx2 : 1'b0);
			assign w_hit_busy_addrs2[i] = w_hit_busy_line2[i] & w_addr_intersect[i];
			assign w_unaligned_in_mq[i] = (r_mq_addr_valid[i] ? r_mq_is_unaligned[i] : 1'b0);
		end
	endgenerate
	always @(posedge clk) begin
		r_hit_busy_addr <= (reset ? 1'b0 : |w_hit_busy_addrs);
		r_hit_busy_addr2 <= (reset ? 1'b0 : |w_hit_busy_addrs2);
		r_hit_busy_line2 <= (reset ? 1'b0 : |w_hit_busy_line2);
		r_fwd_busy_addr2 <= (reset ? 1'b0 : t_push_miss & (t_cache_idx2 == r_cache_idx2));
		r_pop_busy_addr2 <= (reset ? 1'b0 : t_pop_mq);
		r_hit_busy_addrs <= (t_got_req ? w_hit_busy_addrs : {N_MQ_ENTRIES {1'b1}});
		r_hit_busy_addrs2 <= (t_got_req2 ? w_hit_busy_addrs2 : {N_MQ_ENTRIES {1'b1}});
		r_any_unaligned <= (reset ? 1'b0 : |w_unaligned_in_mq | core_mem_va_req[152]);
	end
	always @(posedge clk) r_array_wr_data <= t_array_data;
	always @(posedge clk) begin
		r_cache_accesses <= (reset ? 64'd0 : n_cache_accesses);
		r_cache_hits <= (reset ? 64'd0 : n_cache_hits);
	end
	wire w_drained = |r_rob_inflight == 1'b0;
	always @(posedge clk)
		if (reset) begin
			r_l2_probe_ack <= 1'b0;
			r_page_walk_req_valid <= 1'b0;
			r_page_walk_gnt <= 1'b0;
			r_flush_was_active <= 1'b0;
			r_pending_tlb_miss <= 1'b0;
			r_pending_tlb_zero_page <= 1'b0;
			r_tlb_addr <= 'd0;
			r_did_reload <= 1'b0;
			r_stall_store <= 1'b0;
			r_is_retry <= 1'b0;
			r_flush_complete <= 1'b0;
			r_flush_req <= 1'b0;
			r_flush_cl_req <= 1'b0;
			r_cache_idx <= 'd0;
			r_cache_tag <= 'd0;
			r_cache_idx2 <= 'd0;
			rr_cache_idx2 <= 'd0;
			r_cache_tag2 <= 'd0;
			rr_cache_idx <= 'd0;
			rr_cache_tag <= 'd0;
			r_miss_addr <= 'd0;
			r_miss_idx <= 'd0;
			r_got_req <= 1'b0;
			r_got_req2 <= 1'b0;
			rr_got_req <= 1'b0;
			r_lock_cache <= 1'b0;
			rr_is_retry <= 1'b0;
			rr_did_reload <= 1'b0;
			rr_last_wr <= 1'b0;
			r_last_wr <= 1'b0;
			r_wr_array <= 1'b0;
			r_got_non_mem <= 1'b0;
			r_last_wr2 <= 1'b0;
			r_state <= 4'd0;
			r_mem_req_valid <= 1'b0;
			r_mem_req_uc <= 1'b0;
			r_mem_req_addr <= 'd0;
			r_mem_req_store_data <= 'd0;
			r_mem_req_opcode <= 'd0;
			r_mem_req_tag <= 'd0;
			r_core_mem_rsp_valid <= 1'b0;
			r_store_stalls <= 'd0;
			r_inhibit_write <= 1'b0;
			memq_empty <= 1'b1;
			r_q_priority <= 1'b0;
			r_must_forward <= 1'b0;
			r_must_forward2 <= 1'b0;
		end
		else begin
			r_l2_probe_ack <= n_l2_probe_ack;
			r_page_walk_req_valid <= n_page_walk_req_valid;
			r_page_walk_gnt <= n_page_walk_gnt;
			r_flush_was_active <= n_flush_was_active;
			r_pending_tlb_miss <= n_pending_tlb_miss;
			r_pending_tlb_zero_page <= n_pending_tlb_zero_page;
			r_tlb_addr <= n_tlb_addr;
			r_did_reload <= n_did_reload;
			r_stall_store <= n_stall_store;
			r_is_retry <= n_is_retry;
			r_flush_complete <= n_flush_complete;
			r_flush_req <= n_flush_req;
			r_flush_cl_req <= n_flush_cl_req;
			r_cache_idx <= t_cache_idx;
			r_cache_tag <= t_cache_tag;
			r_cache_idx2 <= t_cache_idx2;
			rr_cache_idx2 <= r_cache_idx2;
			r_cache_tag2 <= t_cache_tag2;
			rr_cache_idx <= r_cache_idx;
			rr_cache_tag <= r_cache_tag;
			r_miss_idx <= t_miss_idx;
			r_miss_addr <= t_miss_addr;
			r_got_req <= t_got_req;
			r_got_req2 <= t_got_req2 | t_replay_req2;
			rr_got_req <= r_got_req;
			r_lock_cache <= n_lock_cache;
			rr_is_retry <= r_is_retry;
			rr_did_reload <= r_did_reload;
			r_last_wr <= n_last_wr;
			rr_last_wr <= r_last_wr;
			r_wr_array <= t_wr_array;
			r_got_non_mem <= t_got_non_mem;
			r_last_wr2 <= n_last_wr2;
			r_state <= n_state;
			r_mem_req_valid <= n_mem_req_valid;
			r_mem_req_uc <= n_mem_req_uc;
			r_mem_req_addr <= n_mem_req_addr;
			r_mem_req_store_data <= n_mem_req_store_data;
			r_mem_req_opcode <= n_mem_req_opcode;
			r_mem_req_tag <= n_mem_req_tag;
			r_core_mem_rsp_valid <= n_core_mem_rsp_valid;
			r_store_stalls <= n_store_stalls;
			r_inhibit_write <= n_inhibit_write;
			memq_empty <= (((((((((mem_q_empty & w_drained) & (&n_mrq_credits)) & !core_mem_va_req_valid) & w_eb_empty) & !t_got_req) & !t_got_req2) & !t_push_miss) & !n_mem_req_valid) & !mem_rsp_valid) & (r_n_inflight == 'd0);
			r_q_priority <= n_q_priority;
			r_must_forward <= t_mh_block & t_pop_mq;
			r_must_forward2 <= t_cm_block & core_mem_va_req_ack;
		end
	always @(posedge clk) begin
		r_req <= n_req;
		r_req2 <= n_req2;
		r_core_mem_rsp <= n_core_mem_rsp;
	end
	always @(*) begin
		if (_sv2v_0)
			;
		t_array_wr_addr = (mem_rsp_reload ? mem_rsp_addr[11:IDX_START] : r_cache_idx);
		t_array_wr_data = (mem_rsp_reload ? mem_rsp_load_data : t_store_shift);
		t_array_wr_en = mem_rsp_reload | t_wr_array;
	end
	always @(negedge clk)
		if (mem_rsp_reload & t_wr_array)
			$stop;
	ram2r1w #(
		.WIDTH(N_TAG_BITS),
		.LG_DEPTH(8)
	) dc_tag(
		.clk(clk),
		.rd_addr0(t_cache_idx),
		.rd_addr1(t_cache_idx2),
		.wr_addr(mem_rsp_addr[11:IDX_START]),
		.wr_data(mem_rsp_addr[31:IDX_STOP]),
		.wr_en(mem_rsp_reload),
		.rd_data0(r_tag_out),
		.rd_data1(r_tag_out2)
	);
	ram2r1w_l1d_data #(.LG_DEPTH(8)) dc_data(
		.clk(clk),
		.rd_addr0(t_cache_idx),
		.rd_addr1(t_cache_idx2),
		.wr_addr(t_array_wr_addr),
		.wr_data(t_array_wr_data),
		.wr_en(t_array_wr_en),
		.wr_byte_en(w_store_byte_en),
		.rd_data0(r_array_out),
		.rd_data1(r_array_out2)
	);
	reg t_dirty_value;
	reg t_write_dirty_en;
	reg [7:0] t_dirty_wr_addr;
	always @(*) begin
		if (_sv2v_0)
			;
		t_dirty_value = 1'b0;
		t_write_dirty_en = 1'b0;
		t_dirty_wr_addr = r_cache_idx;
		if (t_mark_invalid)
			t_write_dirty_en = 1'b1;
		else if (t_push_eb) begin
			t_dirty_wr_addr = n_port1_req_addr[11:IDX_START];
			t_write_dirty_en = 1'b1;
		end
		else if (mem_rsp_reload) begin
			t_dirty_wr_addr = mem_rsp_addr[11:IDX_START];
			t_write_dirty_en = 1'b1;
		end
		else if (t_wr_array) begin
			t_dirty_value = 1'b1;
			t_write_dirty_en = 1'b1;
		end
	end
	ram2r1w #(
		.WIDTH(1),
		.LG_DEPTH(8)
	) dc_dirty(
		.clk(clk),
		.rd_addr0(t_cache_idx),
		.rd_addr1(t_cache_idx2),
		.wr_addr(t_dirty_wr_addr),
		.wr_data(t_dirty_value),
		.wr_en(t_write_dirty_en),
		.rd_data0(r_dirty_out),
		.rd_data1(r_dirty_out2)
	);
	reg t_valid_value;
	reg t_write_valid_en;
	reg [7:0] t_valid_wr_addr;
	always @(*) begin
		if (_sv2v_0)
			;
		t_valid_value = 1'b0;
		t_write_valid_en = 1'b0;
		t_valid_wr_addr = r_cache_idx;
		if (t_mark_invalid)
			t_write_valid_en = 1'b1;
		else if (t_push_eb) begin
			t_write_valid_en = 1'b1;
			t_valid_wr_addr = n_port1_req_addr[11:IDX_START];
		end
		else if (mem_rsp_reload) begin
			t_valid_wr_addr = mem_rsp_addr[11:IDX_START];
			t_valid_value = !r_inhibit_write;
			t_write_valid_en = 1'b1;
		end
	end
	ram2r1w #(
		.WIDTH(1),
		.LG_DEPTH(8)
	) dc_valid(
		.clk(clk),
		.rd_addr0(t_cache_idx),
		.rd_addr1(t_cache_idx2),
		.wr_addr(t_valid_wr_addr),
		.wr_data(t_valid_value),
		.wr_en(t_write_valid_en),
		.rd_data0(r_valid_out),
		.rd_data1(r_valid_out2)
	);
	tlb #(.LG_N(5)) dtlb(
		.clk(clk),
		.reset(reset),
		.priv(priv),
		.clear(clear_tlb),
		.active(paging_active),
		.req(t_tlb_xlat | t_tlb_xlat_replay),
		.va(n_tlb_addr),
		.pa(w_tlb_pa),
		.hit(w_tlb_hit),
		.dirty(w_tlb_dirty),
		.readable(w_tlb_readable),
		.writable(w_tlb_writable),
		.user(w_tlb_user),
		.zero_page(w_zero_page),
		.tlb_hits(tlb_hits),
		.tlb_accesses(tlb_accesses),
		.replace_va(r_tlb_addr),
		.replace(t_reload_tlb),
		.page_walk_rsp(page_walk_rsp)
	);
	reg t_wr_link_reg;
	reg r_paging_active;
	reg [63:0] n_link_reg;
	reg [63:0] r_link_reg;
	reg n_link_reg_val;
	reg r_link_reg_val;
	reg [1:0] r_priv;
	always @(posedge clk) begin
		r_paging_active <= (reset ? 1'b0 : paging_active);
		r_priv <= (reset ? 2'd0 : priv);
	end
	wire w_paging_toggle = r_paging_active ^ paging_active;
	wire w_priv_toggle = priv != r_priv;
	always @(posedge clk)
		if (reset)
			r_link_reg_val <= 1'b0;
		else
			r_link_reg_val <= n_link_reg_val;
	always @(posedge clk)
		if (reset)
			r_link_reg <= 64'd0;
		else if (w_paging_toggle | w_priv_toggle)
			r_link_reg <= 'd0;
		else if (t_wr_link_reg)
			r_link_reg <= n_link_reg;
	wire [6:0] w_shift_amt2 = {r_req2[170:167], 3'd0};
	always @(*) begin
		if (_sv2v_0)
			;
		t_data2 = (r_got_req2 && r_must_forward2 ? r_array_wr_data : r_array_out2);
		t_hit_cache2 = w_port2_hit_cache && r_got_req2;
		t_rsp_dst_valid2 = 1'b0;
		t_rsp_data2 = 'd0;
		t_shift_2 = t_data2 >> w_shift_amt2;
		case (r_req2[162-:4])
			4'd0: begin
				t_rsp_data2 = {{56 {t_shift_2[7]}}, t_shift_2[7:0]};
				t_rsp_dst_valid2 = r_req2[132] & t_hit_cache2;
			end
			4'd1: begin
				t_rsp_data2 = {56'd0, t_shift_2[7:0]};
				t_rsp_dst_valid2 = r_req2[132] & t_hit_cache2;
			end
			4'd2: begin
				t_rsp_data2 = {{48 {t_shift_2[15]}}, t_shift_2[15:0]};
				t_rsp_dst_valid2 = r_req2[132] & t_hit_cache2;
			end
			4'd3: begin
				t_rsp_data2 = {48'd0, t_shift_2[15:0]};
				t_rsp_dst_valid2 = r_req2[132] & t_hit_cache2;
			end
			4'd4: begin
				t_rsp_data2 = {{32 {t_shift_2[31]}}, t_shift_2[31:0]};
				t_rsp_dst_valid2 = r_req2[132] & t_hit_cache2;
			end
			4'd11: begin
				t_rsp_data2 = {32'd0, t_shift_2[31:0]};
				t_rsp_dst_valid2 = r_req2[132] & t_hit_cache2;
			end
			4'd12: begin
				t_rsp_data2 = t_shift_2[63:0];
				t_rsp_dst_valid2 = r_req2[132] & t_hit_cache2;
			end
			default:
				;
		endcase
	end
	wire w_store32 = ((r_req[162-:4] == 4'd7) || (r_req[162-:4] == 4'd14)) || (r_req[162-:4] == 4'd8);
	wire w_store64 = ((r_req[162-:4] == 4'd13) || (r_req[162-:4] == 4'd15)) || (r_req[162-:4] == 4'd9);
	wire [63:0] w_store_mask = (r_req[162-:4] == 4'd5 ? 64'h00000000000000ff : (r_req[162-:4] == 4'd6 ? 64'h000000000000ffff : (w_store32 ? 64'h00000000ffffffff : (w_store64 ? 64'hffffffffffffffff : 'd0))));
	reg [31:0] t_amo32_data;
	reg [63:0] t_amo64_data;
	reg [63:0] r_mtimecmp;
	reg r_mtimecmp_val;
	assign mtimecmp = r_mtimecmp;
	assign mtimecmp_val = r_mtimecmp_val;
	always @(posedge clk)
		if (reset) begin
			r_mtimecmp <= 64'd0;
			r_mtimecmp_val <= 1'b0;
		end
		else begin
			r_mtimecmp_val <= t_wr_store && (r_req[230-:64] == 64'h0000000040004000);
			r_mtimecmp <= r_req[131-:64];
		end
	wire w_match_link = ({r_req[230:171], 4'd0} == r_link_reg) & r_link_reg_val;
	always @(*) begin
		if (_sv2v_0)
			;
		t_data = (r_got_req && r_must_forward ? r_array_wr_data : r_array_out);
		t_hit_cache = (r_got_req & w_cache_port1_hit) & (r_state == 4'd2);
		t_array_data = 'd0;
		t_wr_array = 1'b0;
		t_wr_store = 1'b0;
		t_rsp_dst_valid = 1'b0;
		t_rsp_data = 'd0;
		t_shift = t_data >> {r_req[170:167], 3'd0};
		t_store_shift = {64'd0, r_req[131-:64]} << {r_req[170:167], 3'd0};
		t_store_mask = {64'd0, w_store_mask} << {r_req[170:167], 3'd0};
		t_amo32_data = 32'hdeadbeef;
		t_amo64_data = 64'hd0debabefacebeef;
		t_wr_link_reg = 1'b0;
		n_link_reg = r_link_reg;
		n_link_reg_val = r_link_reg_val;
		case (r_req[158-:5])
			5'd0: begin
				t_amo32_data = t_shift[31:0] + r_req[99:68];
				t_amo64_data = t_shift[63:0] + r_req[131:68];
			end
			5'd1: begin
				t_amo32_data = r_req[99:68];
				t_amo64_data = r_req[131:68];
			end
			5'd8: begin
				t_amo32_data = t_shift[31:0] | r_req[99:68];
				t_amo64_data = t_shift[63:0] | r_req[131:68];
			end
			5'd12: begin
				t_amo32_data = t_shift[31:0] & r_req[99:68];
				t_amo64_data = t_shift[63:0] & r_req[131:68];
			end
			5'd28: begin
				t_amo32_data = (t_shift[31:0] < r_req[99:68] ? r_req[99:68] : t_shift[31:0]);
				t_amo64_data = (t_shift[63:0] < r_req[131:68] ? r_req[131:68] : t_shift[63:0]);
			end
			default:
				;
		endcase
		case (r_req[162-:4])
			4'd0: begin
				t_rsp_data = {{56 {t_shift[7]}}, t_shift[7:0]};
				t_rsp_dst_valid = r_req[132] & t_hit_cache;
			end
			4'd1: begin
				t_rsp_data = {56'd0, t_shift[7:0]};
				t_rsp_dst_valid = r_req[132] & t_hit_cache;
			end
			4'd2: begin
				t_rsp_data = {{48 {t_shift[15]}}, t_shift[15:0]};
				t_rsp_dst_valid = r_req[132] & t_hit_cache;
			end
			4'd3: begin
				t_rsp_data = {48'd0, t_shift[15:0]};
				t_rsp_dst_valid = r_req[132] & t_hit_cache;
			end
			4'd4: begin
				t_rsp_data = {{32 {t_shift[31]}}, t_shift[31:0]};
				t_rsp_dst_valid = r_req[132] & t_hit_cache;
				t_wr_link_reg = r_req[163];
				n_link_reg = {r_req[230:171], 4'd0};
				n_link_reg_val = (r_req[163] ? 1'b1 : r_link_reg_val);
			end
			4'd11: begin
				t_rsp_data = {32'd0, t_shift[31:0]};
				t_rsp_dst_valid = r_req[132] & t_hit_cache;
			end
			4'd12: begin
				t_rsp_data = t_shift[63:0];
				t_rsp_dst_valid = r_req[132] & t_hit_cache;
				t_wr_link_reg = r_req[163];
				n_link_reg = {r_req[230:171], 4'd0};
				n_link_reg_val = (r_req[163] ? 1'b1 : r_link_reg_val);
			end
			4'd5: begin
				t_array_data = (t_store_shift & t_store_mask) | (~t_store_mask & t_data);
				t_wr_store = t_hit_cache && (r_is_retry || r_did_reload);
			end
			4'd6: begin
				t_array_data = (t_store_shift & t_store_mask) | (~t_store_mask & t_data);
				t_wr_store = t_hit_cache && (r_is_retry || r_did_reload);
			end
			4'd7: begin
				t_array_data = (t_store_shift & t_store_mask) | (~t_store_mask & t_data);
				t_wr_store = t_hit_cache && (r_is_retry || r_did_reload);
			end
			4'd13: begin
				t_array_data = (t_store_shift & t_store_mask) | (~t_store_mask & t_data);
				t_wr_store = t_hit_cache && (r_is_retry || r_did_reload);
			end
			4'd9: begin
				t_rsp_data = {63'd0, ~w_match_link};
				t_array_data = (t_store_shift & t_store_mask) | (~t_store_mask & t_data);
				t_wr_store = (w_match_link && t_hit_cache) && ((r_is_retry || r_did_reload) & !r_req[151]);
				t_rsp_dst_valid = r_req[132] & t_hit_cache;
			end
			4'd8: begin
				t_rsp_data = {63'd0, ~w_match_link};
				t_array_data = (t_store_shift & t_store_mask) | (~t_store_mask & t_data);
				t_wr_store = (w_match_link && t_hit_cache) && ((r_is_retry || r_did_reload) & !r_req[151]);
				t_rsp_dst_valid = r_req[132] & t_hit_cache;
			end
			4'd14: begin
				t_rsp_data = {{32 {t_shift[31]}}, t_shift[31:0]};
				t_rsp_dst_valid = r_req[132] & t_hit_cache;
				t_store_shift = {96'd0, t_amo32_data} << {r_req[170:167], 3'd0};
				t_array_data = (t_store_shift & t_store_mask) | (~t_store_mask & t_data);
				t_wr_store = t_hit_cache && ((r_is_retry || r_did_reload) & !r_req[151]);
			end
			4'd15: begin
				t_rsp_data = t_shift[63:0];
				t_rsp_dst_valid = r_req[132] & t_hit_cache;
				t_store_shift = {64'd0, t_amo64_data} << {r_req[170:167], 3'd0};
				t_array_data = (t_store_shift & t_store_mask) | (~t_store_mask & t_data);
				t_wr_store = t_hit_cache && ((r_is_retry || r_did_reload) & !r_req[151]);
			end
			default:
				;
		endcase
		t_wr_array = t_wr_store;
	end
	genvar _gv_i_3;
	generate
		for (_gv_i_3 = 0; _gv_i_3 < BYTES_PER_CL; _gv_i_3 = _gv_i_3 + 1) begin : genblk3
			localparam i = _gv_i_3;
			assign w_store_byte_en[i] = (mem_rsp_valid ? 1'b1 : t_wr_array & t_store_mask[i * 8]);
		end
	endgenerate
	wire w_st_amo_grad = (t_mem_head[166] ? r_graduated[t_mem_head[144-:5]] == 2'b10 : 1'b1);
	wire w_tlb_st_exc = ((w_tlb_hit & paging_active) & (r_req2[166] | r_req2[164])) & !w_tlb_writable;
	wire w_tlb_st_not_dirty = (((w_tlb_hit & paging_active) & (r_req2[166] | r_req2[164])) & w_tlb_writable) & !w_tlb_dirty;
	wire w_flush_hit = (r_tag_out == l2_probe_addr[31:IDX_STOP]) & r_valid_out;
	reg [147:0] t_core_mem_rsp;
	reg t_core_mem_rsp_valid;
	wire w_got_reload_pf = page_walk_rsp_valid & page_walk_rsp[71];
	wire w_port2_rd_hit = t_port2_hit_cache && (!r_hit_busy_addr2 & !r_pending_tlb_miss);
	always @(*) begin
		if (_sv2v_0)
			;
		n_cache_hits = 'd0;
		n_cache_accesses = 'd0;
	end
	always @(*) begin
		if (_sv2v_0)
			;
		t_core_mem_rsp[147-:64] = r_req[230-:64];
		t_core_mem_rsp[83-:64] = r_req[230-:64];
		t_core_mem_rsp[19-:5] = r_req[144-:5];
		t_core_mem_rsp[14-:7] = r_req[139-:7];
		t_core_mem_rsp[7] = 1'b0;
		t_core_mem_rsp[1] = 1'b0;
		t_core_mem_rsp[0] = 1'b0;
		t_core_mem_rsp[6-:5] = 5'd0;
		t_core_mem_rsp_valid = 1'b0;
		t_incr_busy = 1'b0;
		n_stall_store = 1'b0;
		t_push_miss = 1'b0;
		t_req2_pa = r_req2;
		n_pending_tlb_miss = r_pending_tlb_miss;
		n_pending_tlb_zero_page = r_pending_tlb_zero_page;
		if (r_got_req2) begin
			t_core_mem_rsp[147-:64] = r_req2[230-:64];
			t_core_mem_rsp[19-:5] = r_req2[144-:5];
			t_core_mem_rsp[14-:7] = r_req2[139-:7];
			t_req2_pa[230-:64] = {32'd0, w_tlb_pa};
			if (r_pending_tlb_miss) begin
				n_pending_tlb_miss = 1'b0;
				n_pending_tlb_zero_page = 1'b0;
			end
			if (drain_ds_complete) begin
				t_core_mem_rsp[7] = r_req2[132];
				t_core_mem_rsp[1] = r_req2[151];
				t_core_mem_rsp[6-:5] = r_req2[150-:5];
				t_core_mem_rsp[83-:64] = r_req2[230-:64];
				t_core_mem_rsp_valid = 1'b1;
			end
			else if (r_req2[162-:4] == 4'd10) begin
				if (r_req2[153])
					t_core_mem_rsp[6-:5] = 5'd0;
				else
					t_core_mem_rsp[6-:5] = r_req2[150-:5];
				t_core_mem_rsp[7] = r_req2[132];
				t_core_mem_rsp[1] = 1'b1;
				t_core_mem_rsp[83-:64] = r_req2[230-:64];
				t_core_mem_rsp_valid = 1'b1;
			end
			else if (!w_tlb_hit & w_zero_page) begin
				t_core_mem_rsp[7] = r_req2[132];
				t_core_mem_rsp[1] = 1'b1;
				t_core_mem_rsp[6-:5] = 5'd13;
				t_core_mem_rsp[83-:64] = r_req2[230-:64];
				t_core_mem_rsp_valid = 1'b1;
			end
			else if (!w_tlb_hit) begin
				n_pending_tlb_miss = 1'b1;
				n_pending_tlb_zero_page = w_zero_page;
				if (r_pending_tlb_miss)
					$stop;
			end
			else if (w_tlb_st_exc) begin
				t_core_mem_rsp[7] = r_req2[132];
				t_core_mem_rsp[1] = 1'b1;
				t_core_mem_rsp[6-:5] = 5'd15;
				t_core_mem_rsp[83-:64] = r_req2[230-:64];
				t_core_mem_rsp_valid = 1'b1;
			end
			else if (r_req2[164] || r_req2[163])
				t_push_miss = 1'b1;
			else if (r_req2[166]) begin
				t_push_miss = 1'b1;
				t_incr_busy = 1'b1;
				n_stall_store = 1'b1;
				t_core_mem_rsp[7] = 1'b0;
				t_core_mem_rsp_valid = 1'b1;
				t_core_mem_rsp[1] = r_req2[153];
				t_core_mem_rsp[0] = w_tlb_st_not_dirty;
				t_core_mem_rsp[83-:64] = r_req2[230-:64];
			end
			else if (w_port2_rd_hit & !r_got_rd_retry) begin
				t_core_mem_rsp[147-:64] = t_rsp_data2[63:0];
				t_core_mem_rsp[7] = t_rsp_dst_valid2;
				t_core_mem_rsp_valid = 1'b1;
				t_core_mem_rsp[1] = r_req2[153];
			end
			else
				t_push_miss = 1'b1;
		end
	end
	wire w_got_hit_or_idle = (r_got_req ? w_cache_port1_hit : 1'b1);
	wire w_got_hit = (r_got_req ? w_cache_port1_hit : 1'b0);
	wire w_got_clean_miss = (r_got_req ? w_cache_port1_clean_miss : 1'b0);
	wire w_mh_block = (r_got_req && r_last_wr) && (r_cache_idx == t_mem_head[178:171]);
	wire w_got_rd_retry = ((((!w_mh_block & !mem_q_empty) & w_got_hit) & !r_lock_cache) & !n_pending_tlb_miss) & !(t_mem_head[166] | t_mem_head[164]);
	reg t_new_req;
	reg [6:0] t_new_req_c;
	reg t_accept;
	always @(*) begin
		if (_sv2v_0)
			;
		t_cm_block = (r_got_req && r_last_wr) && (r_cache_idx == core_mem_va_req[178:171]);
		t_cm_block_stall = t_cm_block && !(r_did_reload || r_is_retry);
		t_new_req_c[0] = w_got_hit_or_idle;
		t_new_req_c[1] = !(mem_q_almost_full | mem_q_full);
		t_new_req_c[2] = 1'b1;
		t_new_req_c[3] = !((r_last_wr2 & (r_cache_idx2 == core_mem_va_req[178:171])) & !core_mem_va_req[166]);
		t_new_req_c[4] = !(n_pending_tlb_miss | r_pending_tlb_miss);
		t_new_req_c[5] = !t_cm_block_stall;
		t_new_req_c[6] = !r_rob_inflight[core_mem_va_req[144-:5]];
		t_new_req = core_mem_va_req_valid & (&t_new_req_c);
	end
	always @(posedge clk) r_got_rd_retry <= (reset ? 1'b0 : w_got_rd_retry & t_new_req);
	reg t_old_ack;
	always @(*) begin
		if (_sv2v_0)
			;
		t_old_ack = 1'b0;
		n_flush_was_active = r_flush_was_active;
		n_page_walk_gnt = r_page_walk_gnt | page_walk_rsp_gnt;
		n_l2_probe_ack = 1'b0;
		t_reload_tlb = 1'b0;
		n_page_walk_req_valid = 1'b0;
		t_got_rd_retry = 1'b0;
		t_port2_hit_cache = w_port2_hit_cache;
		n_state = r_state;
		t_miss_idx = r_miss_idx;
		t_miss_addr = r_miss_addr;
		t_cache_idx = 'd0;
		t_cache_tag = 'd0;
		t_got_req = 1'b0;
		t_replay_req2 = 1'b0;
		t_got_non_mem = 1'b0;
		n_last_wr = 1'b0;
		t_got_miss = 1'b0;
		t_dirty_miss = 1'b0;
		t_push_eb = 1'b0;
		n_req = r_req;
		t_tlb_xlat_replay = 1'b0;
		core_store_data_ack = 1'b0;
		n_port1_req_valid = 1'b0;
		n_port1_req_uc = 1'b0;
		n_port1_req_addr = r_mem_req_addr;
		n_port1_req_store_data = r_mem_req_store_data;
		n_port1_req_opcode = r_mem_req_opcode;
		n_port1_req_tag = r_mem_req_tag;
		t_pop_mq = 1'b0;
		n_core_mem_rsp_valid = t_core_mem_rsp_valid;
		n_core_mem_rsp[147-:64] = t_core_mem_rsp[147-:64];
		n_core_mem_rsp[83-:64] = t_core_mem_rsp[83-:64];
		n_core_mem_rsp[19-:5] = t_core_mem_rsp[19-:5];
		n_core_mem_rsp[14-:7] = t_core_mem_rsp[14-:7];
		n_core_mem_rsp[7] = t_core_mem_rsp[7];
		n_core_mem_rsp[1] = t_core_mem_rsp[1];
		n_core_mem_rsp[0] = t_core_mem_rsp[0];
		n_core_mem_rsp[6-:5] = t_core_mem_rsp[6-:5];
		n_store_stalls = r_store_stalls;
		n_flush_req = r_flush_req | flush_req;
		n_flush_cl_req = r_flush_cl_req | l2_probe_val;
		n_flush_complete = 1'b0;
		t_addr = 'd0;
		n_inhibit_write = r_inhibit_write;
		t_mark_invalid = 1'b0;
		n_is_retry = 1'b0;
		t_reset_graduated = 1'b0;
		t_force_clear_busy = 1'b0;
		n_q_priority = !r_q_priority;
		n_did_reload = 1'b0;
		n_lock_cache = r_lock_cache;
		t_mh_block = (r_got_req && r_last_wr) && (r_cache_idx == t_mem_head[178:171]);
		case (r_state)
			4'd0: begin
				n_state = 4'd1;
				t_cache_idx = 'd0;
			end
			4'd1: begin
				t_cache_idx = r_cache_idx + 'd1;
				t_mark_invalid = 1'b1;
				if (r_cache_idx == 255) begin
					n_state = 4'd2;
					n_flush_complete = 1'b1;
				end
				else
					t_cache_idx = r_cache_idx + 'd1;
			end
			4'd2: begin
				if (r_got_req) begin
					if (w_got_hit) begin
						t_reset_graduated = r_req[166];
						if (r_req[166] == 1'b0) begin
							n_core_mem_rsp[147-:64] = t_rsp_data[63:0];
							n_core_mem_rsp[7] = t_rsp_dst_valid;
							n_core_mem_rsp_valid = 1'b1;
							if (t_core_mem_rsp_valid)
								$stop;
							n_core_mem_rsp[1] = r_req[153];
						end
					end
					else if ((r_valid_out && r_dirty_out) && (r_tag_out != r_cache_tag)) begin
						t_got_miss = 1'b1;
						t_dirty_miss = 1'b1;
						n_inhibit_write = 1'b1;
						if ((r_hit_busy_addr && r_is_retry) || !r_hit_busy_addr) begin
							n_port1_req_addr = {r_tag_out, r_cache_idx, 4'd0};
							n_port1_req_opcode = 4'd7;
							n_port1_req_store_data = t_data;
							n_inhibit_write = 1'b1;
							t_miss_idx = r_cache_idx;
							t_miss_addr = r_req[230-:64];
							n_lock_cache = 1'b1;
							if ((rr_cache_idx == r_cache_idx) && rr_last_wr) begin
								t_cache_idx = r_cache_idx;
								n_state = 4'd4;
							end
							else begin
								t_push_eb = 1'b1;
								n_state = 4'd5;
							end
						end
					end
					else begin
						t_got_miss = 1'b1;
						n_inhibit_write = 1'b0;
						if (((r_hit_busy_addr && r_is_retry) || !r_hit_busy_addr) || r_lock_cache) begin
							t_miss_idx = r_cache_idx;
							t_miss_addr = r_req[230-:64];
							t_cache_idx = r_cache_idx;
							if ((rr_cache_idx == r_cache_idx) && rr_last_wr) begin
								n_port1_req_addr = {r_tag_out, r_cache_idx, 4'd0};
								n_lock_cache = 1'b1;
								n_port1_req_opcode = 4'd7;
								n_port1_req_tag = 8;
								t_dirty_miss = 1'b1;
								n_state = 4'd4;
							end
							else begin
								n_lock_cache = 1'b0;
								n_port1_req_addr = {r_req[198:171], 4'd0};
								n_port1_req_opcode = 4'd4;
								n_port1_req_tag = 8;
								n_state = 4'd3;
								n_port1_req_valid = 1'b1;
							end
						end
						else begin
							$display("r_valid_out = %b r_dirty_out = %b r_tag_out = %x r_cache_tag = %x line %x cycle %d", r_valid_out, r_dirty_out, r_tag_out, r_cache_tag, r_cache_idx, r_cycle);
							$display("r_hit_busy_addr %b,  r_is_retry  %b r_hit_busy_addr %b r_lock_cache %b", r_hit_busy_addr, r_is_retry, r_hit_busy_addr, r_lock_cache);
							$stop;
						end
					end
				end
				else if (n_pending_tlb_miss) begin
					n_state = 4'd12;
					n_page_walk_gnt = 1'b0;
					n_page_walk_req_valid = 1'b1;
				end
				if ((((((!mem_q_empty & !t_got_miss) & !r_lock_cache) & !n_pending_tlb_miss) & !w_eb_port1_hit) & !w_eb_full) & w_two_free_credits) begin
					if (!t_mh_block & (r_mq_inflight[r_mq_head_ptr[2:0]] == 1'b0)) begin
						if (t_mem_head[166] | t_mem_head[164]) begin
							if (w_st_amo_grad && (core_store_data_valid ? t_mem_head[144-:5] == core_store_data[4-:5] : 1'b0)) begin
								t_pop_mq = 1'b1;
								core_store_data_ack = 1'b1;
								n_req = t_mem_head;
								n_req[131-:64] = core_store_data[68-:64];
								t_cache_idx = t_mem_head[178:171];
								t_cache_tag = t_mem_head[198:179];
								t_addr = t_mem_head[230-:64];
								t_got_req = 1'b1;
								n_is_retry = 1'b1;
								n_last_wr = 1'b1;
							end
							else if (drain_ds_complete && dead_rob_mask[t_mem_head[144-:5]]) begin
								t_pop_mq = 1'b1;
								t_force_clear_busy = 1'b1;
							end
						end
						else begin
							t_pop_mq = 1'b1;
							n_req = t_mem_head;
							t_cache_idx = t_mem_head[178:171];
							t_cache_tag = t_mem_head[198:179];
							t_addr = t_mem_head[230-:64];
							t_got_req = 1'b1;
							n_is_retry = 1'b1;
							t_got_rd_retry = 1'b1;
						end
					end
				end
				if (t_new_req)
					t_old_ack = 1'b1;
				else if (((r_flush_req && mem_q_empty) && !(r_got_req && r_last_wr)) && !w_eb_full) begin
					n_state = 4'd6;
					if (!mem_q_empty)
						$stop;
					if (r_got_req && r_last_wr)
						$stop;
					t_cache_idx = 'd0;
					n_flush_req = 1'b0;
				end
				else if ((((r_flush_cl_req & mem_q_empty) & w_queues_drained) & !(r_got_req && r_last_wr)) & !(((n_page_walk_req_valid | t_got_miss) | r_wr_array) | t_wr_array)) begin
					if (!mem_q_empty)
						$stop;
					if (r_got_req && r_last_wr)
						$stop;
					t_cache_idx = l2_probe_addr[11:IDX_START];
					n_flush_cl_req = 1'b0;
					n_flush_was_active = 1'b1;
					n_state = 4'd9;
				end
			end
			4'd4: begin
				t_push_eb = 1'b1;
				n_state = 4'd5;
				n_port1_req_store_data = t_data;
			end
			4'd5: begin
				t_cache_idx = r_req[178:171];
				t_cache_tag = r_req[198:179];
				n_last_wr = r_req[166];
				t_got_req = 1'b1;
				t_addr = r_req[230-:64];
				n_did_reload = 1'b1;
				n_state = 4'd2;
			end
			4'd3:
				if (mem_rsp_reload && (mem_rsp_tag == 8)) begin
					n_state = 4'd11;
					n_inhibit_write = 1'b0;
				end
			4'd11: begin
				t_cache_idx = r_req[178:171];
				t_cache_tag = r_req[198:179];
				n_last_wr = r_req[166];
				t_got_req = 1'b1;
				t_addr = r_req[230-:64];
				n_did_reload = 1'b1;
				n_state = 4'd2;
			end
			4'd9: begin
				if ((w_flush_hit & r_link_reg_val) & (r_link_reg[31:0] == {r_tag_out, r_cache_idx, 4'd0}))
					$stop;
				if (r_dirty_out & w_flush_hit) begin
					n_port1_req_addr = {r_tag_out, r_cache_idx, 4'd0};
					n_port1_req_opcode = 4'd7;
					n_port1_req_store_data = t_data;
					n_state = 4'd10;
					n_inhibit_write = 1'b1;
					n_port1_req_valid = 1'b1;
				end
				else begin
					n_state = (r_flush_was_active ? 4'd2 : 4'd12);
					n_flush_was_active = 1'b0;
					t_mark_invalid = w_flush_hit;
					n_l2_probe_ack = 1'b1;
				end
			end
			4'd10:
				if (w_queues_drained) begin
					n_state = (n_flush_was_active ? 4'd2 : 4'd12);
					n_flush_was_active = 1'b0;
					n_inhibit_write = 1'b0;
					n_l2_probe_ack = 1'b1;
				end
			4'd6: begin
				t_cache_idx = r_cache_idx + 'd1;
				if (!r_dirty_out) begin
					t_mark_invalid = 1'b1;
					t_cache_idx = r_cache_idx + 'd1;
					if (r_cache_idx == 255) begin
						n_state = 4'd2;
						n_flush_complete = 1'b1;
					end
				end
				else begin
					n_port1_req_addr = {r_tag_out, r_cache_idx, 4'd0};
					n_port1_req_opcode = 4'd7;
					n_port1_req_store_data = t_data;
					n_port1_req_tag = {1'b1, {3 {1'b1}}};
					n_state = (r_cache_idx == 255 ? 4'd8 : 4'd7);
					n_inhibit_write = 1'b1;
					t_push_eb = 1'b1;
				end
			end
			4'd8: begin
				t_cache_idx = r_cache_idx;
				if (mem_rsp_valid) begin
					n_state = 4'd2;
					n_inhibit_write = 1'b0;
					n_flush_complete = 1'b1;
				end
			end
			4'd7: begin
				t_cache_idx = r_cache_idx;
				if (mem_rsp_valid) begin
					n_state = 4'd6;
					n_inhibit_write = 1'b0;
				end
			end
			4'd12:
				if (page_walk_rsp_valid) begin
					t_reload_tlb = page_walk_rsp[71] == 1'b0;
					n_state = 4'd13;
				end
				else if (n_flush_cl_req & w_queues_drained) begin
					n_state = 4'd9;
					n_flush_cl_req = 1'b0;
					t_cache_idx = l2_probe_addr[11:IDX_START];
					n_flush_was_active = 1'b0;
				end
			4'd13: begin
				n_page_walk_gnt = 1'b0;
				n_state = 4'd2;
				t_replay_req2 = 1'b1;
				t_tlb_xlat_replay = 1'b1;
			end
			default:
				;
		endcase
	end
	always @(negedge clk) begin
		if (t_push_miss && mem_q_full) begin
			$display("attempting to push to a full memory queue");
			$stop;
		end
		if (t_pop_mq && mem_q_empty) begin
			$display("attempting to pop an empty memory queue");
			$stop;
		end
	end
	wire w_reload_line = ((core_mem_va_req[178:171] == r_miss_idx) & (r_state != 4'd2)) | ((core_mem_va_req[178:171] == t_miss_idx) & t_got_miss);
	always @(*) begin
		if (_sv2v_0)
			;
		t_cache_idx2 = 'd0;
		t_cache_tag2 = 'd0;
		n_req2 = r_req2;
		core_mem_va_req_ack = 1'b0;
		t_got_req2 = 1'b0;
		n_last_wr2 = 1'b0;
		t_tlb_xlat = 1'b0;
		n_tlb_addr = r_tlb_addr;
		t_accept = (t_new_req & (t_got_req ? n_last_wr : 1'b1)) & !w_reload_line;
		if (w_got_reload_pf) begin
			n_req2[162-:4] = 4'd10;
			n_req2[166] = 1'b0;
			n_req2[151] = 1'b1;
			n_req2[150-:5] = (r_req2[166] | r_req2[164] ? 5'd15 : 5'd13);
		end
		else if (t_replay_req2) begin
			t_cache_idx2 = r_req2[178:171];
			t_cache_tag2 = r_req2[198:179];
			t_got_req2 = 1'b1;
			t_tlb_xlat = 1'b1;
			n_tlb_addr = r_req2[230-:64];
			n_last_wr2 = r_req2[166];
		end
		else if (t_accept) begin
			t_cache_idx2 = core_mem_va_req[178:171];
			t_cache_tag2 = core_mem_va_req[198:179];
			n_req2 = core_mem_va_req;
			core_mem_va_req_ack = 1'b1;
			t_got_req2 = 1'b1;
			t_tlb_xlat = 1'b1;
			n_tlb_addr = core_mem_va_req[230-:64];
			n_last_wr2 = core_mem_va_req[166];
			if ((r_state != 4'd2) && (r_miss_idx == t_cache_idx2))
				$stop;
		end
	end
	always @(*) begin
		if (_sv2v_0)
			;
		n_mem_req_valid = n_port1_req_valid;
		n_mem_req_uc = n_port1_req_uc;
		n_mem_req_addr = n_port1_req_addr;
		n_mem_req_store_data = n_port1_req_store_data;
		n_mem_req_opcode = n_port1_req_opcode;
		n_mem_req_tag = n_port1_req_tag;
		t_pop_eb = 1'b0;
		if (n_port2_req_valid) begin
			n_mem_req_valid = n_port2_req_valid;
			n_mem_req_uc = n_port2_req_uc;
			n_mem_req_addr = n_port2_req_addr;
			n_mem_req_store_data = n_port2_req_store_data;
			n_mem_req_opcode = n_port2_req_opcode;
			if (n_mem_req_opcode == 4'd7)
				$stop;
			n_mem_req_tag = n_port2_req_tag;
		end
		else if ((!(n_port1_req_valid | n_port2_req_valid) & !w_eb_empty) & w_one_free_credit) begin
			t_pop_eb = 1'b1;
			n_mem_req_valid = 1'b1;
			n_mem_req_uc = 1'b0;
			n_mem_req_addr = r_sb[(r_eb_head_ptr[0:0] * 160) + 159-:32];
			n_mem_req_store_data = r_sb[(r_eb_head_ptr[0:0] * 160) + 127-:128];
			n_mem_req_opcode = 4'd7;
			n_mem_req_tag = {1'b1, {3 {1'b1}}};
		end
	end
	wire w_decr_credit = n_mem_req_valid & !mem_rsp_valid;
	wire w_incr_credit = !n_mem_req_valid & mem_rsp_valid;
	always @(*) begin
		if (_sv2v_0)
			;
		n_mrq_credits = r_mrq_credits;
		if (w_decr_credit) begin
			n_mrq_credits = r_mrq_credits - 'd1;
			if (r_mrq_credits == 'd0) begin
				$display("trying to push with no free credits,  mem_rdy %b, w_gen_early_req %b, r_state = %d", mem_rdy, w_gen_early_req, r_state);
				$stop;
			end
		end
		else if (w_incr_credit)
			n_mrq_credits = r_mrq_credits + 'd1;
	end
	reg [15:0] r_credits;
	reg [15:0] n_credits;
	always @(*) begin
		if (_sv2v_0)
			;
		n_credits = r_credits;
		if (r_mem_req_valid)
			n_credits[mem_req[135-:4]] = 1'b1;
		if (mem_rsp_valid)
			n_credits[mem_rsp_tag] = 1'b0;
	end
	always @(posedge clk) r_credits <= (reset ? 'd0 : n_credits);
	always @(*) begin
		if (_sv2v_0)
			;
		n_eb_head_ptr = r_eb_head_ptr;
		n_eb_tail_ptr = r_eb_tail_ptr;
		if (t_push_eb)
			n_eb_tail_ptr = r_eb_tail_ptr + 'd1;
		if (t_pop_eb)
			n_eb_head_ptr = r_eb_head_ptr + 'd1;
	end
	initial _sv2v_0 = 0;
endmodule

module l1i (
	clk,
	reset,
	l1i_state,
	priv,
	page_table_root,
	paging_active,
	clear_tlb,
	mode64,
	page_walk_req_va,
	page_walk_req_valid,
	page_walk_rsp_valid,
	page_walk_rsp,
	flush_req,
	flush_complete,
	restart_pc,
	restart_src_pc,
	restart_src_is_indirect,
	restart_valid,
	restart_ack,
	retire_valid,
	retired_call,
	retired_ret,
	retire_reg_ptr,
	retire_reg_data,
	retire_reg_valid,
	branch_pc_valid,
	branch_pc,
	took_branch,
	branch_fault,
	branch_pht_idx,
	insn,
	insn_valid,
	insn_ack,
	insn_two,
	insn_valid_two,
	insn_ack_two,
	mem_req_valid,
	mem_req_addr,
	mem_req_opcode,
	mem_rsp_valid,
	mem_rsp_load_data,
	cache_accesses,
	cache_hits,
	tlb_accesses,
	tlb_hits
);
	reg _sv2v_0;
	input wire clk;
	input wire reset;
	output wire [3:0] l1i_state;
	input wire paging_active;
	input wire clear_tlb;
	input wire [1:0] priv;
	input wire [63:0] page_table_root;
	input wire mode64;
	output wire [63:0] page_walk_req_va;
	output wire page_walk_req_valid;
	input wire page_walk_rsp_valid;
	input wire [71:0] page_walk_rsp;
	input wire flush_req;
	output wire flush_complete;
	input wire [63:0] restart_pc;
	input wire [63:0] restart_src_pc;
	input wire restart_src_is_indirect;
	input wire restart_valid;
	output wire restart_ack;
	input wire retire_valid;
	input wire retired_call;
	input wire retired_ret;
	input wire [4:0] retire_reg_ptr;
	input wire [63:0] retire_reg_data;
	input wire retire_reg_valid;
	input wire branch_pc_valid;
	input wire [63:0] branch_pc;
	input wire took_branch;
	input wire branch_fault;
	input wire [15:0] branch_pht_idx;
	output reg [177:0] insn;
	output wire insn_valid;
	input wire insn_ack;
	output reg [177:0] insn_two;
	output wire insn_valid_two;
	input wire insn_ack_two;
	output wire mem_req_valid;
	localparam L1I_NUM_SETS = 256;
	localparam L1I_CL_LEN = 16;
	localparam L1I_CL_LEN_BITS = 128;
	localparam LG_WORDS_PER_CL = 2;
	localparam WORDS_PER_CL = 4;
	localparam N_TAG_BITS = 27;
	localparam IDX_START = 4;
	localparam IDX_STOP = 12;
	localparam WORD_START = 2;
	localparam WORD_STOP = 4;
	localparam N_FQ_ENTRIES = 8;
	localparam RETURN_STACK_ENTRIES = 8;
	localparam PHT_ENTRIES = 65536;
	localparam BTB_ENTRIES = 128;
	output wire [63:0] mem_req_addr;
	output wire [3:0] mem_req_opcode;
	input wire mem_rsp_valid;
	input wire [127:0] mem_rsp_load_data;
	output wire [63:0] cache_accesses;
	output wire [63:0] cache_hits;
	output wire [63:0] tlb_accesses;
	output wire [63:0] tlb_hits;
	wire in_32b_mode = mode64 == 1'b0;
	reg [26:0] t_cache_tag;
	reg [26:0] r_cache_tag;
	wire [26:0] r_tag_out;
	reg r_pht_update;
	wire [1:0] r_pht_out;
	wire [1:0] r_pht_update_out;
	reg [1:0] t_pht_val;
	reg t_do_pht_wr;
	wire [15:0] n_pht_idx;
	reg [15:0] r_pht_idx;
	reg [15:0] r_pht_update_idx;
	reg [15:0] t_retire_pht_idx;
	reg r_take_br;
	reg [63:0] r_btb [127:0];
	reg [127:0] r_btb_valid;
	wire [15:0] r_jump_out;
	reg [7:0] t_cache_idx;
	reg [7:0] r_cache_idx;
	wire [127:0] r_array_out;
	reg r_mem_req_valid;
	reg n_mem_req_valid;
	reg [63:0] r_mem_req_addr;
	reg [63:0] n_mem_req_addr;
	reg [177:0] r_fq [7:0];
	reg [3:0] r_fq_head_ptr;
	reg [3:0] n_fq_head_ptr;
	reg [3:0] r_fq_next_head_ptr;
	reg [3:0] n_fq_next_head_ptr;
	reg [3:0] r_fq_next_tail_ptr;
	reg [3:0] n_fq_next_tail_ptr;
	reg [3:0] r_fq_next3_tail_ptr;
	reg [3:0] n_fq_next3_tail_ptr;
	reg [3:0] r_fq_next4_tail_ptr;
	reg [3:0] n_fq_next4_tail_ptr;
	reg [3:0] r_fq_tail_ptr;
	reg [3:0] n_fq_tail_ptr;
	reg r_resteer_bubble;
	reg n_resteer_bubble;
	reg fq_full;
	reg fq_next_empty;
	reg fq_empty;
	reg fq_full2;
	reg fq_full3;
	reg fq_full4;
	reg [511:0] r_spec_return_stack;
	reg [511:0] r_arch_return_stack;
	reg [2:0] n_arch_rs_tos;
	reg [2:0] r_arch_rs_tos;
	reg [2:0] n_spec_rs_tos;
	reg [2:0] r_spec_rs_tos;
	reg [2:0] t_next_spec_rs_tos;
	reg [15:0] n_arch_gbl_hist;
	reg [15:0] r_arch_gbl_hist;
	reg [15:0] n_spec_gbl_hist;
	reg [15:0] r_spec_gbl_hist;
	reg [15:0] r_last_spec_gbl_hist;
	reg [1:0] t_insn_idx;
	reg [63:0] n_cache_accesses;
	reg [63:0] r_cache_accesses;
	reg [63:0] n_cache_hits;
	reg [63:0] r_cache_hits;
	function [31:0] select_cl32;
		input reg [127:0] cl;
		input reg [1:0] pos;
		reg [31:0] w32;
		begin
			case (pos)
				2'd0: w32 = cl[31:0];
				2'd1: w32 = cl[63:32];
				2'd2: w32 = cl[95:64];
				2'd3: w32 = cl[127:96];
			endcase
			select_cl32 = w32;
		end
	endfunction
	function [3:0] select_pd;
		input reg [15:0] cl;
		input reg [1:0] pos;
		reg [3:0] j;
		begin
			case (pos)
				2'd0: j = cl[3:0];
				2'd1: j = cl[7:4];
				2'd2: j = cl[11:8];
				2'd3: j = cl[15:12];
			endcase
			select_pd = j;
		end
	endfunction
	reg [63:0] r_pc;
	reg [63:0] n_pc;
	reg [63:0] r_miss_pc;
	reg [63:0] n_miss_pc;
	reg [63:0] r_cache_pc;
	reg [63:0] n_cache_pc;
	reg [63:0] r_btb_pc;
	reg [3:0] n_state;
	reg [3:0] r_state;
	assign l1i_state = r_state;
	reg r_restart_req;
	reg n_restart_req;
	reg r_restart_ack;
	reg n_restart_ack;
	reg r_req;
	reg n_req;
	wire r_valid_out;
	reg t_miss;
	reg t_hit;
	reg t_tag_match;
	reg t_push_insn;
	reg t_push_insn2;
	reg t_push_insn3;
	reg t_push_insn4;
	reg t_unaligned_fetch;
	reg n_page_fault;
	reg r_page_fault;
	reg n_tlb_miss;
	reg r_tlb_miss;
	wire [63:0] w_tlb_pc;
	wire w_tlb_hit;
	reg t_reload_tlb;
	reg t_clear_fq;
	reg r_flush_req;
	reg n_flush_req;
	reg r_flush_complete;
	reg n_flush_complete;
	reg t_take_br;
	reg t_is_cflow;
	reg t_update_spec_hist;
	reg [31:0] t_insn_data;
	reg [31:0] t_insn_data2;
	reg [31:0] t_insn_data3;
	reg [31:0] t_insn_data4;
	reg [63:0] t_jal_simm;
	reg [63:0] t_br_simm;
	reg t_is_call;
	reg t_is_ret;
	reg [2:0] t_branch_cnt;
	reg [4:0] t_branch_marker;
	reg [4:0] t_spec_branch_marker;
	reg [2:0] t_first_branch;
	reg t_init_pht;
	reg [15:0] r_init_pht_idx;
	reg [15:0] n_init_pht_idx;
	localparam PP = 32;
	localparam SEXT = 48;
	reg [177:0] t_insn;
	reg [177:0] t_insn2;
	reg [177:0] t_insn3;
	reg [177:0] t_insn4;
	reg [3:0] t_pd;
	reg [63:0] r_cycle;
	always @(posedge clk) r_cycle <= (reset ? 'd0 : r_cycle + 'd1);
	assign flush_complete = r_flush_complete;
	assign insn_valid = !fq_empty;
	assign insn_valid_two = !(fq_next_empty || fq_empty);
	assign restart_ack = r_restart_ack;
	assign mem_req_valid = r_mem_req_valid;
	assign mem_req_addr = r_mem_req_addr;
	assign mem_req_opcode = 4'd4;
	assign cache_hits = r_cache_hits;
	assign cache_accesses = r_cache_accesses;
	assign page_walk_req_valid = r_tlb_miss;
	assign page_walk_req_va = r_miss_pc;
	wire [63:0] w_restart_pc = restart_pc;
	always @(*) begin
		if (_sv2v_0)
			;
		n_fq_tail_ptr = r_fq_tail_ptr;
		n_fq_head_ptr = r_fq_head_ptr;
		n_fq_next_head_ptr = r_fq_next_head_ptr;
		n_fq_next_tail_ptr = r_fq_next_tail_ptr;
		n_fq_next3_tail_ptr = r_fq_next3_tail_ptr;
		n_fq_next4_tail_ptr = r_fq_next4_tail_ptr;
		fq_empty = r_fq_head_ptr == r_fq_tail_ptr;
		fq_next_empty = r_fq_next_head_ptr == r_fq_tail_ptr;
		fq_full = (r_fq_head_ptr != r_fq_tail_ptr) && (r_fq_head_ptr[2:0] == r_fq_tail_ptr[2:0]);
		fq_full2 = ((r_fq_head_ptr != r_fq_next_tail_ptr) && (r_fq_head_ptr[2:0] == r_fq_next_tail_ptr[2:0])) || fq_full;
		fq_full3 = ((r_fq_head_ptr != r_fq_next3_tail_ptr) && (r_fq_head_ptr[2:0] == r_fq_next3_tail_ptr[2:0])) || fq_full2;
		fq_full4 = ((r_fq_head_ptr != r_fq_next4_tail_ptr) && (r_fq_head_ptr[2:0] == r_fq_next4_tail_ptr[2:0])) || fq_full3;
		insn = r_fq[r_fq_head_ptr[2:0]];
		insn_two = r_fq[r_fq_next_head_ptr[2:0]];
		if (t_push_insn4) begin
			n_fq_tail_ptr = r_fq_tail_ptr + 'd4;
			n_fq_next_tail_ptr = r_fq_next_tail_ptr + 'd4;
			n_fq_next3_tail_ptr = r_fq_next3_tail_ptr + 'd4;
			n_fq_next4_tail_ptr = r_fq_next4_tail_ptr + 'd4;
		end
		else if (t_push_insn3) begin
			n_fq_tail_ptr = r_fq_tail_ptr + 'd3;
			n_fq_next_tail_ptr = r_fq_next_tail_ptr + 'd3;
			n_fq_next3_tail_ptr = r_fq_next3_tail_ptr + 'd3;
			n_fq_next4_tail_ptr = r_fq_next4_tail_ptr + 'd3;
		end
		else if (t_push_insn2) begin
			n_fq_tail_ptr = r_fq_tail_ptr + 'd2;
			n_fq_next_tail_ptr = r_fq_next_tail_ptr + 'd2;
			n_fq_next3_tail_ptr = r_fq_next3_tail_ptr + 'd2;
			n_fq_next4_tail_ptr = r_fq_next4_tail_ptr + 'd2;
		end
		else if (t_push_insn) begin
			n_fq_tail_ptr = r_fq_tail_ptr + 'd1;
			n_fq_next_tail_ptr = r_fq_next_tail_ptr + 'd1;
			n_fq_next3_tail_ptr = r_fq_next3_tail_ptr + 'd1;
			n_fq_next4_tail_ptr = r_fq_next4_tail_ptr + 'd1;
		end
		if (insn_ack && !insn_ack_two) begin
			n_fq_head_ptr = r_fq_head_ptr + 'd1;
			n_fq_next_head_ptr = r_fq_next_head_ptr + 'd1;
		end
		else if (insn_ack && insn_ack_two) begin
			n_fq_head_ptr = r_fq_head_ptr + 'd2;
			n_fq_next_head_ptr = r_fq_next_head_ptr + 'd2;
		end
	end
	always @(posedge clk)
		if (t_push_insn)
			r_fq[r_fq_tail_ptr[2:0]] <= t_insn;
		else if (t_push_insn2) begin
			r_fq[r_fq_tail_ptr[2:0]] <= t_insn;
			r_fq[r_fq_next_tail_ptr[2:0]] <= t_insn2;
		end
		else if (t_push_insn3) begin
			r_fq[r_fq_tail_ptr[2:0]] <= t_insn;
			r_fq[r_fq_next_tail_ptr[2:0]] <= t_insn2;
			r_fq[r_fq_next3_tail_ptr[2:0]] <= t_insn3;
		end
		else if (t_push_insn4) begin
			r_fq[r_fq_tail_ptr[2:0]] <= t_insn;
			r_fq[r_fq_next_tail_ptr[2:0]] <= t_insn2;
			r_fq[r_fq_next3_tail_ptr[2:0]] <= t_insn3;
			r_fq[r_fq_next4_tail_ptr[2:0]] <= t_insn4;
		end
	always @(posedge clk)
		if (reset)
			r_btb_valid <= 'd0;
		else if (restart_valid && restart_src_is_indirect)
			r_btb_valid[restart_src_pc[8:2]] <= 1'b1;
	always @(posedge clk)
		if (restart_valid && restart_src_is_indirect)
			r_btb[restart_src_pc[8:2]] <= restart_pc;
	always @(posedge clk) r_btb_pc <= (reset ? 'd0 : (r_btb_valid[n_cache_pc[8:2]] ? r_btb[n_cache_pc[8:2]] : 'd0));
	always @(*) begin
		if (_sv2v_0)
			;
		n_page_fault = r_page_fault;
		n_pc = r_pc;
		n_miss_pc = r_miss_pc;
		n_cache_pc = 'd0;
		n_state = r_state;
		n_restart_ack = 1'b0;
		n_flush_req = r_flush_req | flush_req;
		n_flush_complete = 1'b0;
		t_cache_idx = 'd0;
		t_cache_tag = 'd0;
		n_req = 1'b0;
		n_mem_req_valid = 1'b0;
		n_mem_req_addr = r_mem_req_addr;
		n_resteer_bubble = 1'b0;
		t_next_spec_rs_tos = r_spec_rs_tos + 'd1;
		n_restart_req = restart_valid | r_restart_req;
		t_tag_match = r_tag_out == w_tlb_pc[38:IDX_STOP];
		t_miss = r_req && !(r_valid_out && t_tag_match);
		t_hit = r_req && (r_valid_out && t_tag_match);
		t_insn_idx = r_cache_pc[3:WORD_START];
		t_pd = select_pd(r_jump_out, t_insn_idx);
		t_insn_data = select_cl32(r_array_out, t_insn_idx);
		t_insn_data2 = select_cl32(r_array_out, t_insn_idx + 2'd1);
		t_insn_data3 = select_cl32(r_array_out, t_insn_idx + 2'd2);
		t_insn_data4 = select_cl32(r_array_out, t_insn_idx + 2'd3);
		t_branch_marker = {1'b1, select_pd(r_jump_out, 'd3) != 4'd0, select_pd(r_jump_out, 'd2) != 4'd0, select_pd(r_jump_out, 'd1) != 4'd0, select_pd(r_jump_out, 'd0) != 4'd0} >> t_insn_idx;
		t_spec_branch_marker = ({1'b1, select_pd(r_jump_out, 'd3) != 4'd0, select_pd(r_jump_out, 'd2) != 4'd0, select_pd(r_jump_out, 'd1) != 4'd0, select_pd(r_jump_out, 'd0) != 4'd0} >> t_insn_idx) & {4'b1111, !((t_pd == 4'd1) && !r_pht_out[1])};
		t_first_branch = 'd7;
		casez (t_spec_branch_marker)
			5'bzzzz1: t_first_branch = 'd0;
			5'bzzz10: t_first_branch = 'd1;
			5'bzz100: t_first_branch = 'd2;
			5'bz1000: t_first_branch = 'd3;
			5'b10000: t_first_branch = 'd4;
			default: t_first_branch = 'd7;
		endcase
		t_branch_cnt = (({2'd0, select_pd(r_jump_out, 'd0) != 4'd0} + {2'd0, select_pd(r_jump_out, 'd1) != 4'd0}) + {2'd0, select_pd(r_jump_out, 'd2) != 4'd0}) + {2'd0, select_pd(r_jump_out, 'd3) != 4'd0};
		t_jal_simm = {{43 {t_insn_data[31]}}, t_insn_data[31], t_insn_data[19:12], t_insn_data[20], t_insn_data[30:21], 1'b0};
		t_br_simm = {{51 {t_insn_data[31]}}, t_insn_data[31], t_insn_data[7], t_insn_data[30:25], t_insn_data[11:8], 1'b0};
		t_clear_fq = 1'b0;
		t_push_insn = 1'b0;
		t_push_insn2 = 1'b0;
		t_push_insn3 = 1'b0;
		t_push_insn4 = 1'b0;
		t_unaligned_fetch = 1'b0;
		t_take_br = 1'b0;
		t_is_cflow = 1'b0;
		t_update_spec_hist = 1'b0;
		t_is_call = 1'b0;
		t_is_ret = 1'b0;
		t_init_pht = 1'b0;
		n_init_pht_idx = r_init_pht_idx;
		t_reload_tlb = 1'b0;
		n_tlb_miss = 1'b0;
		case (r_state)
			4'd0: n_state = 4'd7;
			4'd7: begin
				t_init_pht = 1'b1;
				n_init_pht_idx = r_init_pht_idx + 'd1;
				if (r_init_pht_idx == 65535) begin
					n_state = 4'd5;
					t_cache_idx = 0;
				end
			end
			4'd1:
				if (n_restart_req) begin
					n_restart_ack = 1'b1;
					n_restart_req = 1'b0;
					n_pc = w_restart_pc;
					n_state = 4'd2;
					t_clear_fq = 1'b1;
				end
			4'd2: begin
				t_cache_idx = r_pc[11:IDX_START];
				t_cache_tag = r_pc[38:IDX_STOP];
				n_cache_pc = r_pc;
				n_req = 1'b1;
				n_pc = r_pc + 'd4;
				if (r_resteer_bubble)
					;
				else if (n_flush_req) begin
					n_flush_req = 1'b0;
					t_clear_fq = 1'b1;
					n_state = 4'd5;
					t_cache_idx = 0;
				end
				else if (n_restart_req) begin
					n_restart_ack = 1'b1;
					n_restart_req = 1'b0;
					n_pc = w_restart_pc;
					n_req = 1'b0;
					n_state = 4'd2;
					t_clear_fq = 1'b1;
					n_page_fault = 1'b0;
				end
				else if (r_page_fault) begin
					if (!fq_full) begin
						n_page_fault = 1'b0;
						t_push_insn = 1'b1;
					end
				end
				else if ((!w_tlb_hit & r_req) && paging_active) begin
					n_state = 4'd8;
					n_pc = r_pc;
					n_miss_pc = r_cache_pc;
					n_tlb_miss = 1'b1;
				end
				else if (t_miss) begin
					n_state = 4'd3;
					n_mem_req_addr = (paging_active ? {w_tlb_pc[63:4], {4 {1'b0}}} : {r_cache_pc[63:4], {4 {1'b0}}});
					n_mem_req_valid = 1'b1;
					n_miss_pc = r_cache_pc;
					n_pc = r_pc;
				end
				else if (t_hit && !fq_full) begin
					t_update_spec_hist = t_pd != 4'd0;
					if ((t_pd == 4'd5) || (t_pd == 4'd3)) begin
						t_is_cflow = 1'b1;
						t_take_br = 1'b1;
						t_is_call = t_pd == 4'd5;
						n_pc = r_cache_pc + t_jal_simm;
					end
					else if ((t_pd == 4'd1) && r_pht_out[1]) begin
						t_is_cflow = 1'b1;
						t_take_br = 1'b1;
						n_pc = r_cache_pc + t_br_simm;
					end
					else if (t_pd == 4'd2) begin
						t_is_cflow = 1'b1;
						t_is_ret = 1'b1;
						t_take_br = 1'b1;
						n_pc = r_spec_return_stack[t_next_spec_rs_tos * 64+:64];
					end
					else if ((t_pd == 4'd4) || (t_pd == 4'd6)) begin
						t_is_cflow = 1'b1;
						t_take_br = 1'b1;
						t_is_call = t_pd == 4'd6;
						n_pc = r_btb_pc;
					end
					n_resteer_bubble = t_is_cflow;
					if (!t_is_cflow) begin
						if ((t_first_branch == 'd4) && !fq_full4) begin
							t_push_insn4 = 1'b1;
							t_cache_idx = r_cache_idx + 'd1;
							n_cache_pc = r_cache_pc + 'd16;
							t_cache_tag = n_cache_pc[38:IDX_STOP];
							n_pc = r_cache_pc + 'd20;
						end
						else if ((t_first_branch == 'd3) && !fq_full3) begin
							t_push_insn3 = 1'b1;
							n_cache_pc = r_cache_pc + 'd12;
							n_pc = r_cache_pc + 'd16;
							t_cache_tag = n_cache_pc[38:IDX_STOP];
							if (t_insn_idx != 0)
								t_cache_idx = r_cache_idx + 'd1;
						end
						else if ((t_first_branch == 'd2) && !fq_full2) begin
							t_push_insn2 = 1'b1;
							n_pc = r_cache_pc + 'd8;
							n_cache_pc = r_cache_pc + 'd8;
							t_cache_tag = n_cache_pc[38:IDX_STOP];
							n_pc = r_cache_pc + 'd12;
							if (t_insn_idx == 2)
								t_cache_idx = r_cache_idx + 'd1;
						end
						else
							t_push_insn = 1'b1;
					end
					else
						t_push_insn = 1'b1;
				end
				else if (t_hit && fq_full) begin
					n_pc = r_pc;
					n_miss_pc = r_cache_pc;
					n_state = 4'd6;
				end
			end
			4'd3:
				if (mem_rsp_valid)
					n_state = 4'd4;
			4'd4: begin
				t_cache_idx = r_miss_pc[11:IDX_START];
				t_cache_tag = r_miss_pc[38:IDX_STOP];
				if (n_flush_req) begin
					n_flush_req = 1'b0;
					t_clear_fq = 1'b1;
					n_state = 4'd5;
					t_cache_idx = 0;
				end
				else if (n_restart_req) begin
					n_restart_ack = 1'b1;
					n_restart_req = 1'b0;
					n_pc = w_restart_pc;
					n_req = 1'b0;
					n_state = 4'd2;
					t_clear_fq = 1'b1;
					n_page_fault = 1'b0;
				end
				else if (!fq_full) begin
					n_cache_pc = r_miss_pc;
					n_req = 1'b1;
					n_state = 4'd2;
				end
			end
			4'd5: begin
				if (r_cache_idx == 255) begin
					n_flush_complete = 1'b1;
					n_state = 4'd1;
				end
				t_cache_idx = r_cache_idx + 'd1;
			end
			4'd6: begin
				t_cache_idx = r_miss_pc[11:IDX_START];
				t_cache_tag = r_miss_pc[38:IDX_STOP];
				n_cache_pc = r_miss_pc;
				if (n_flush_req) begin
					n_flush_req = 1'b0;
					t_clear_fq = 1'b1;
					n_state = 4'd5;
					t_cache_idx = 0;
				end
				else if (!fq_full) begin
					n_req = 1'b1;
					n_state = 4'd2;
				end
				else if (n_restart_req) begin
					n_restart_ack = 1'b1;
					n_restart_req = 1'b0;
					n_pc = w_restart_pc;
					n_req = 1'b0;
					n_state = 4'd2;
					t_clear_fq = 1'b1;
					n_page_fault = 1'b0;
				end
			end
			4'd8:
				if (page_walk_rsp_valid) begin
					n_page_fault = page_walk_rsp[71];
					t_reload_tlb = page_walk_rsp[71] == 1'b0;
					n_state = 4'd9;
				end
			4'd9: begin
				n_cache_pc = r_miss_pc;
				t_cache_idx = r_miss_pc[11:IDX_START];
				t_cache_tag = r_miss_pc[38:IDX_STOP];
				n_state = 4'd2;
				n_req = 1'b1;
			end
			default:
				;
		endcase
	end
	always @(*) begin
		if (_sv2v_0)
			;
		n_cache_accesses = 'd0;
		n_cache_hits = 'd0;
	end
	always @(*) begin
		if (_sv2v_0)
			;
		t_insn[177-:32] = t_insn_data;
		t_insn[145] = r_page_fault;
		t_insn[144-:64] = r_cache_pc;
		t_insn[80-:64] = n_pc;
		t_insn[16] = t_take_br;
		t_insn[15-:16] = r_pht_idx;
		t_insn2[177-:32] = t_insn_data2;
		t_insn2[145] = 1'b0;
		t_insn2[144-:64] = r_cache_pc + 'd4;
		t_insn2[80-:64] = 'd0;
		t_insn2[16] = 1'b0;
		t_insn2[15-:16] = 'd0;
		t_insn3[177-:32] = t_insn_data3;
		t_insn3[145] = 1'b0;
		t_insn3[144-:64] = r_cache_pc + 'd8;
		t_insn3[80-:64] = 'd0;
		t_insn3[16] = 1'b0;
		t_insn3[15-:16] = 'd0;
		t_insn4[177-:32] = t_insn_data4;
		t_insn4[145] = 1'b0;
		t_insn4[144-:64] = r_cache_pc + 'd12;
		t_insn4[80-:64] = 'd0;
		t_insn4[16] = 1'b0;
		t_insn4[15-:16] = 'd0;
	end
	reg t_wr_valid_ram_en;
	reg t_valid_ram_value;
	reg [7:0] t_valid_ram_idx;
	compute_pht_idx cpi0(
		.pc(n_cache_pc),
		.hist(r_spec_gbl_hist),
		.idx(n_pht_idx)
	);
	always @(*) begin
		if (_sv2v_0)
			;
		t_retire_pht_idx = branch_pht_idx;
	end
	always @(*) begin
		if (_sv2v_0)
			;
		t_wr_valid_ram_en = mem_rsp_valid || (r_state == 4'd5);
		t_valid_ram_value = r_state != 4'd5;
		t_valid_ram_idx = (mem_rsp_valid ? r_mem_req_addr[11:IDX_START] : r_cache_idx);
	end
	always @(*) begin
		if (_sv2v_0)
			;
		t_pht_val = r_pht_update_out;
		t_do_pht_wr = r_pht_update;
		case (r_pht_update_out)
			2'd0:
				if (r_take_br)
					t_pht_val = 2'd1;
				else
					t_do_pht_wr = 1'b0;
			2'd1: t_pht_val = (r_take_br ? 2'd2 : 2'd0);
			2'd2: t_pht_val = (r_take_br ? 2'd3 : 2'd1);
			2'd3:
				if (!r_take_br)
					t_pht_val = 2'd2;
				else
					t_do_pht_wr = 1'b0;
		endcase
	end
	always @(posedge clk)
		if (reset) begin
			r_pht_idx <= 'd0;
			r_last_spec_gbl_hist <= 'd0;
			r_pht_update <= 1'b0;
			r_pht_update_idx <= 'd0;
			r_take_br <= 1'b0;
		end
		else begin
			r_pht_idx <= n_pht_idx;
			r_last_spec_gbl_hist <= r_spec_gbl_hist;
			r_pht_update <= branch_pc_valid;
			r_pht_update_idx <= t_retire_pht_idx;
			r_take_br <= took_branch;
		end
	tlb #(
		.LG_N(6),
		.ISIDE(1)
	) itlb(
		.clk(clk),
		.reset(reset),
		.priv(priv),
		.clear(clear_tlb),
		.active(paging_active),
		.req(n_req),
		.va(n_cache_pc),
		.pa(w_tlb_pc),
		.hit(w_tlb_hit),
		.dirty(),
		.readable(),
		.writable(),
		.user(),
		.zero_page(),
		.tlb_hits(tlb_hits),
		.tlb_accesses(tlb_accesses),
		.replace_va(r_miss_pc),
		.replace(t_reload_tlb),
		.page_walk_rsp(page_walk_rsp)
	);
	ram2r1w #(
		.WIDTH(2),
		.LG_DEPTH(16)
	) pht(
		.clk(clk),
		.rd_addr0(n_pht_idx),
		.rd_addr1(t_retire_pht_idx),
		.wr_addr((t_init_pht ? r_init_pht_idx : r_pht_update_idx)),
		.wr_data((t_init_pht ? 2'd1 : t_pht_val)),
		.wr_en(t_init_pht || t_do_pht_wr),
		.rd_data0(r_pht_out),
		.rd_data1(r_pht_update_out)
	);
	ram1r1w #(
		.WIDTH(1),
		.LG_DEPTH(8)
	) valid_array(
		.clk(clk),
		.rd_addr(t_cache_idx),
		.wr_addr(t_valid_ram_idx),
		.wr_data(t_valid_ram_value),
		.wr_en(t_wr_valid_ram_en),
		.rd_data(r_valid_out)
	);
	ram1r1w #(
		.WIDTH(N_TAG_BITS),
		.LG_DEPTH(8)
	) tag_array(
		.clk(clk),
		.rd_addr(t_cache_idx),
		.wr_addr(r_mem_req_addr[11:IDX_START]),
		.wr_data(r_mem_req_addr[38:IDX_STOP]),
		.wr_en(mem_rsp_valid),
		.rd_data(r_tag_out)
	);
	ram1r1w #(
		.WIDTH(L1I_CL_LEN_BITS),
		.LG_DEPTH(8)
	) insn_array(
		.clk(clk),
		.rd_addr(t_cache_idx),
		.wr_addr(r_mem_req_addr[11:IDX_START]),
		.wr_data({mem_rsp_load_data[127:96], mem_rsp_load_data[95:64], mem_rsp_load_data[63:32], mem_rsp_load_data[31:0]}),
		.wr_en(mem_rsp_valid),
		.rd_data(r_array_out)
	);
	wire [3:0] w_pd0;
	wire [3:0] w_pd1;
	wire [3:0] w_pd2;
	wire [3:0] w_pd3;
	predecode pd0(
		.insn(mem_rsp_load_data[31:0]),
		.pd(w_pd0)
	);
	predecode pd1(
		.insn(mem_rsp_load_data[63:32]),
		.pd(w_pd1)
	);
	predecode pd2(
		.insn(mem_rsp_load_data[95:64]),
		.pd(w_pd2)
	);
	predecode pd3(
		.insn(mem_rsp_load_data[127:96]),
		.pd(w_pd3)
	);
	ram1r1w #(
		.WIDTH(16),
		.LG_DEPTH(8)
	) pd_data(
		.clk(clk),
		.rd_addr(t_cache_idx),
		.wr_addr(r_mem_req_addr[11:IDX_START]),
		.wr_data({w_pd3, w_pd2, w_pd1, w_pd0}),
		.wr_en(mem_rsp_valid),
		.rd_data(r_jump_out)
	);
	always @(*) begin
		if (_sv2v_0)
			;
		n_spec_rs_tos = r_spec_rs_tos;
		if (n_restart_ack)
			n_spec_rs_tos = r_arch_rs_tos;
		else if (t_is_call)
			n_spec_rs_tos = r_spec_rs_tos - 'd1;
		else if (t_is_ret)
			n_spec_rs_tos = r_spec_rs_tos + 'd1;
	end
	always @(posedge clk)
		if (t_is_call)
			r_spec_return_stack[r_spec_rs_tos * 64+:64] <= r_cache_pc + 'd4;
		else if (n_restart_ack)
			r_spec_return_stack <= r_arch_return_stack;
	always @(posedge clk)
		if ((retire_reg_valid && retire_valid) && retired_call)
			r_arch_return_stack[r_arch_rs_tos * 64+:64] <= retire_reg_data;
	always @(*) begin
		if (_sv2v_0)
			;
		n_arch_rs_tos = r_arch_rs_tos;
		if (retire_valid && retired_call)
			n_arch_rs_tos = r_arch_rs_tos - 'd1;
		else if (retire_valid && retired_ret)
			n_arch_rs_tos = r_arch_rs_tos + 'd1;
	end
	always @(*) begin
		if (_sv2v_0)
			;
		n_spec_gbl_hist = r_spec_gbl_hist;
		if (n_restart_ack)
			n_spec_gbl_hist = n_arch_gbl_hist;
		else if (t_update_spec_hist)
			n_spec_gbl_hist = {r_spec_gbl_hist[14:0], t_take_br};
	end
	always @(*) begin
		if (_sv2v_0)
			;
		n_arch_gbl_hist = r_arch_gbl_hist;
		if (branch_pc_valid)
			n_arch_gbl_hist = {r_arch_gbl_hist[14:0], took_branch};
	end
	always @(posedge clk)
		if (reset) begin
			r_tlb_miss <= 1'b0;
			r_state <= 4'd0;
			r_page_fault <= 1'b0;
			r_init_pht_idx <= 'd0;
			r_pc <= 'd0;
			r_miss_pc <= 'd0;
			r_cache_pc <= 'd0;
			r_restart_ack <= 1'b0;
			r_cache_idx <= 'd0;
			r_cache_tag <= 'd0;
			r_req <= 1'b0;
			r_mem_req_valid <= 1'b0;
			r_mem_req_addr <= 'd0;
			r_fq_head_ptr <= 'd0;
			r_fq_next_head_ptr <= 'd1;
			r_fq_next_tail_ptr <= 'd1;
			r_fq_next3_tail_ptr <= 'd1;
			r_fq_next4_tail_ptr <= 'd1;
			r_fq_tail_ptr <= 'd0;
			r_restart_req <= 1'b0;
			r_flush_req <= 1'b0;
			r_flush_complete <= 1'b0;
			r_spec_rs_tos <= 7;
			r_arch_rs_tos <= 7;
			r_arch_gbl_hist <= 'd0;
			r_spec_gbl_hist <= 'd0;
			r_cache_hits <= 'd0;
			r_cache_accesses <= 'd0;
			r_resteer_bubble <= 1'b0;
		end
		else begin
			r_tlb_miss <= n_tlb_miss;
			r_state <= n_state;
			r_page_fault <= n_page_fault;
			r_init_pht_idx <= n_init_pht_idx;
			r_pc <= n_pc;
			r_miss_pc <= n_miss_pc;
			r_cache_pc <= n_cache_pc;
			r_restart_ack <= n_restart_ack;
			r_cache_idx <= t_cache_idx;
			r_cache_tag <= t_cache_tag;
			r_req <= n_req;
			r_mem_req_valid <= n_mem_req_valid;
			r_mem_req_addr <= n_mem_req_addr;
			r_fq_head_ptr <= (t_clear_fq ? 'd0 : n_fq_head_ptr);
			r_fq_next_head_ptr <= (t_clear_fq ? 'd1 : n_fq_next_head_ptr);
			r_fq_next_tail_ptr <= (t_clear_fq ? 'd1 : n_fq_next_tail_ptr);
			r_fq_next3_tail_ptr <= (t_clear_fq ? 'd2 : n_fq_next3_tail_ptr);
			r_fq_next4_tail_ptr <= (t_clear_fq ? 'd3 : n_fq_next4_tail_ptr);
			r_fq_tail_ptr <= (t_clear_fq ? 'd0 : n_fq_tail_ptr);
			r_restart_req <= n_restart_req;
			r_flush_req <= n_flush_req;
			r_flush_complete <= n_flush_complete;
			r_spec_rs_tos <= n_spec_rs_tos;
			r_arch_rs_tos <= n_arch_rs_tos;
			r_arch_gbl_hist <= n_arch_gbl_hist;
			r_spec_gbl_hist <= n_spec_gbl_hist;
			r_cache_hits <= n_cache_hits;
			r_cache_accesses <= n_cache_accesses;
			r_resteer_bubble <= n_resteer_bubble;
		end
	initial _sv2v_0 = 0;
endmodule

module ram2r1w (
	clk,
	rd_addr0,
	rd_addr1,
	wr_addr,
	wr_data,
	wr_en,
	rd_data0,
	rd_data1
);
	input wire clk;
	parameter WIDTH = 1;
	parameter LG_DEPTH = 1;
	input wire [LG_DEPTH - 1:0] rd_addr0;
	input wire [LG_DEPTH - 1:0] rd_addr1;
	input wire [LG_DEPTH - 1:0] wr_addr;
	input wire [WIDTH - 1:0] wr_data;
	input wire wr_en;
	output wire [WIDTH - 1:0] rd_data0;
	output wire [WIDTH - 1:0] rd_data1;
	ram1r1w #(
		.WIDTH(WIDTH),
		.LG_DEPTH(LG_DEPTH)
	) b0(
		.clk(clk),
		.rd_addr(rd_addr0),
		.wr_addr(wr_addr),
		.wr_data(wr_data),
		.wr_en(wr_en),
		.rd_data(rd_data0)
	);
	ram1r1w #(
		.WIDTH(WIDTH),
		.LG_DEPTH(LG_DEPTH)
	) b1(
		.clk(clk),
		.rd_addr(rd_addr1),
		.wr_addr(wr_addr),
		.wr_data(wr_data),
		.wr_en(wr_en),
		.rd_data(rd_data1)
	);
endmodule
module ram2r1w_l1d_data (
	clk,
	rd_addr0,
	rd_addr1,
	wr_addr,
	wr_data,
	wr_en,
	wr_byte_en,
	rd_data0,
	rd_data1
);
	input wire clk;
	parameter LG_DEPTH = 1;
	localparam WIDTH = 128;
	input wire [LG_DEPTH - 1:0] rd_addr0;
	input wire [LG_DEPTH - 1:0] rd_addr1;
	input wire [LG_DEPTH - 1:0] wr_addr;
	input wire [127:0] wr_data;
	input wire wr_en;
	input wire [15:0] wr_byte_en;
	output wire [127:0] rd_data0;
	output wire [127:0] rd_data1;
	ram1r1w_l1d_data #(.LG_DEPTH(LG_DEPTH)) b0(
		.clk(clk),
		.rd_addr(rd_addr0),
		.wr_addr(wr_addr),
		.wr_data(wr_data),
		.wr_en(wr_en),
		.wr_byte_en(wr_byte_en),
		.rd_data(rd_data0)
	);
	ram1r1w_l1d_data #(.LG_DEPTH(LG_DEPTH)) b1(
		.clk(clk),
		.rd_addr(rd_addr1),
		.wr_addr(wr_addr),
		.wr_data(wr_data),
		.wr_en(wr_en),
		.wr_byte_en(wr_byte_en),
		.rd_data(rd_data1)
	);
endmodule



module nu_divider (
	clk,
	reset,
	flush,
	wb_slot_used,
	inA,
	inB,
	rob_ptr_in,
	prf_ptr_in,
	is_signed_div,
	is_rem,
	is_w,
	start_div,
	y,
	rob_ptr_out,
	prf_ptr_out,
	ready,
	complete
);
	reg _sv2v_0;
	parameter LG_W = 5;
	localparam W = 1 << LG_W;
	localparam W2 = 2 * W;
	input wire clk;
	input wire reset;
	input wire flush;
	input wire wb_slot_used;
	input wire [63:0] inA;
	input wire [63:0] inB;
	input wire [4:0] rob_ptr_in;
	input wire [6:0] prf_ptr_in;
	input wire is_signed_div;
	input wire is_rem;
	input wire is_w;
	input wire start_div;
	output reg [63:0] y;
	output reg [4:0] rob_ptr_out;
	output reg [6:0] prf_ptr_out;
	output reg ready;
	output reg complete;
	reg [2:0] r_state;
	reg [2:0] n_state;
	reg r_is_signed;
	reg n_is_signed;
	reg r_sign;
	reg n_sign;
	reg r_rem_sign;
	reg n_rem_sign;
	reg r_is_rem_op;
	reg n_is_rem_op;
	reg [4:0] r_rob_ptr;
	reg [4:0] n_rob_ptr;
	reg [6:0] r_gpr_prf_ptr;
	reg [6:0] n_gpr_prf_ptr;
	reg [W - 1:0] r_A;
	reg [W - 1:0] n_A;
	reg [W - 1:0] r_B;
	reg [W - 1:0] n_B;
	reg [W - 1:0] r_lastA;
	reg [W - 1:0] n_lastA;
	reg [W - 1:0] r_lastB;
	reg [W - 1:0] n_lastB;
	reg r_last_signed;
	reg n_last_signed;
	reg [W - 1:0] r_last_ss;
	reg [W - 1:0] n_last_ss;
	reg [W2 - 1:0] r_last_Y;
	reg [W2 - 1:0] n_last_Y;
	reg [W2 - 1:0] r_last_R;
	reg [W2 - 1:0] n_last_R;
	reg r_last_valid;
	reg n_last_valid;
	reg [W2 - 1:0] r_Y;
	reg [W2 - 1:0] n_Y;
	reg [W2 - 1:0] r_D;
	reg [W2 - 1:0] n_D;
	reg [W2 - 1:0] r_R;
	reg [W2 - 1:0] n_R;
	reg [W - 1:0] t_ss;
	reg r_is_w;
	reg n_is_w;
	reg [LG_W + 1:0] r_idx;
	reg [LG_W + 1:0] n_idx;
	reg t_bit;
	reg t_valid;
	reg t_clr;
	wire [W - 1:0] srcA = inA[W - 1:0];
	wire [W - 1:0] srcB = inB[W - 1:0];
	always @(posedge clk)
		if (reset) begin
			r_state <= 3'd0;
			r_rob_ptr <= 'd0;
			r_gpr_prf_ptr <= 'd0;
			r_is_signed <= 1'b0;
			r_sign <= 1'b0;
			r_rem_sign <= 1'b0;
			r_is_rem_op <= 1'b0;
			r_A <= 'd0;
			r_B <= 'd0;
			r_Y <= 'd0;
			r_D <= 'd0;
			r_R <= 'd0;
			r_lastA <= 64'd0;
			r_lastB <= 64'd0;
			r_last_Y <= 'd0;
			r_last_R <= 'd0;
			r_last_ss <= 'd0;
			r_last_signed <= 1'b0;
			r_last_valid <= 1'b0;
			r_idx <= 'd0;
			r_is_w <= 1'b0;
		end
		else begin
			r_state <= n_state;
			r_rob_ptr <= n_rob_ptr;
			r_gpr_prf_ptr <= n_gpr_prf_ptr;
			r_is_signed <= n_is_signed;
			r_sign <= n_sign;
			r_rem_sign <= n_rem_sign;
			r_is_rem_op <= n_is_rem_op;
			r_A <= n_A;
			r_B <= n_B;
			r_Y <= n_Y;
			r_D <= n_D;
			r_R <= n_R;
			r_lastA <= n_lastA;
			r_lastB <= n_lastB;
			r_last_Y <= n_last_Y;
			r_last_R <= n_last_R;
			r_last_ss <= n_last_ss;
			r_last_signed <= n_last_signed;
			r_last_valid <= n_last_valid;
			r_idx <= n_idx;
			r_is_w <= n_is_w;
		end
	always @(posedge clk)
		if (reset | t_clr)
			t_ss <= 'd0;
		else if (t_valid)
			t_ss <= t_ss | ({{W - 1 {1'b0}}, t_bit} << r_idx);
	wire w_match_prev = (((r_lastA == r_A) & (r_lastB == r_B)) & (r_last_signed == r_is_signed)) & r_last_valid;
	wire [LG_W + 1:0] w_clz_R;
	wire [LG_W + 1:0] w_clz_D;
	count_leading_zeros #(.LG_N(LG_W + 1)) clz0(
		.in({r_R[W2 - 2:0], 1'b0}),
		.y(w_clz_R)
	);
	count_leading_zeros #(.LG_N(LG_W + 1)) clz1(
		.in(r_D),
		.y(w_clz_D)
	);
	wire [LG_W + 1:0] w_clz_delta = w_clz_R - w_clz_D;
	always @(*) begin
		if (_sv2v_0)
			;
		n_rob_ptr = r_rob_ptr;
		n_gpr_prf_ptr = r_gpr_prf_ptr;
		n_state = r_state;
		n_is_signed = r_is_signed;
		n_sign = r_sign;
		n_rem_sign = r_rem_sign;
		n_is_rem_op = r_is_rem_op;
		n_A = r_A;
		n_B = r_B;
		n_Y = r_Y;
		n_D = r_D;
		n_R = r_R;
		n_lastA = r_lastA;
		n_lastB = r_lastB;
		n_last_signed = r_last_signed;
		n_last_Y = r_last_Y;
		n_last_R = r_last_R;
		n_last_ss = r_last_ss;
		n_last_valid = r_last_valid;
		n_idx = r_idx;
		t_bit = 1'b0;
		t_clr = 1'b0;
		t_valid = 1'b0;
		n_is_w = r_is_w;
		ready = (r_state == 3'd0) & !start_div;
		rob_ptr_out = r_rob_ptr;
		prf_ptr_out = r_gpr_prf_ptr;
		y = r_Y[W - 1:0];
		complete = 1'b0;
		(* full_case, parallel_case *)
		case (r_state)
			3'd0: begin
				t_clr = 1'b1;
				n_is_w = is_w;
				n_rob_ptr = rob_ptr_in;
				n_gpr_prf_ptr = prf_ptr_in;
				n_is_rem_op = is_rem;
				n_is_signed = is_signed_div;
				n_state = (start_div ? 3'd2 : 3'd0);
				n_idx = W - 1;
				n_sign = srcA[W - 1] ^ srcB[W - 1];
				n_rem_sign = srcA[W - 1];
				n_A = (is_signed_div & srcA[W - 1] ? ~srcA + 'd1 : srcA);
				n_B = (is_signed_div & srcB[W - 1] ? ~srcB + 'd1 : srcB);
				n_D = {n_B, {W {1'b0}}};
				n_R = {{W {1'b0}}, n_A};
			end
			3'd2: begin
				n_state = 3'd1;
				if (w_clz_delta <= 'd64) begin
					n_R = r_R << (w_clz_R - w_clz_D);
					n_idx = r_idx - (w_clz_R - w_clz_D);
					n_state = (n_idx == 8'hff ? 3'd3 : 3'd1);
				end
			end
			3'd1: begin
				if ({r_R[W2 - 2:0], 1'b0} >= r_D) begin
					n_R = {r_R[W2 - 2:0], 1'b0} - r_D;
					t_bit = 1'b1;
					t_valid = 1'b1;
				end
				else begin
					n_R = {r_R[W2 - 2:0], 1'b0};
					t_bit = 1'b0;
					t_valid = 1'b1;
				end
				n_state = (w_match_prev | flush ? 3'd5 : (r_idx == 'd0 ? 3'd3 : 3'd1));
				n_idx = r_idx - 'd1;
			end
			3'd3: begin
				n_state = 3'd6;
				n_lastA = r_A;
				n_lastB = r_B;
				n_last_signed = r_is_signed;
				n_last_valid = 1'b1;
				n_Y[W - 1:0] = t_ss;
				n_Y[W2 - 1:W] = n_R[W2 - 1:W];
				n_last_Y = n_Y;
				n_last_R = n_R;
				n_last_ss = t_ss;
				if (r_is_signed && r_sign)
					n_Y[W - 1:0] = ~t_ss + 'd1;
				if (r_is_signed && r_rem_sign)
					n_Y[W2 - 1:W] = ~n_R[W2 - 1:W] + 'd1;
				if (r_is_rem_op)
					n_Y[W - 1:0] = n_Y[W2 - 1:W];
				if (r_is_w)
					n_Y = {{96 {n_Y[31]}}, n_Y[31:0]};
			end
			3'd4: begin
				complete = 1'b1;
				n_state = 3'd0;
			end
			3'd5: begin
				n_Y = r_last_Y;
				n_R = r_last_R;
				if (r_is_signed && r_sign)
					n_Y[W - 1:0] = ~r_last_ss + 'd1;
				if (r_is_signed && r_rem_sign)
					n_Y[W2 - 1:W] = ~n_R[W2 - 1:W] + 'd1;
				if (r_is_rem_op)
					n_Y[W - 1:0] = n_Y[W2 - 1:W];
				if (r_is_w)
					n_Y = {{96 {n_Y[31]}}, n_Y[31:0]};
				n_state = 3'd6;
			end
			3'd6:
				if (wb_slot_used == 1'b0) begin
					n_state = 3'd0;
					complete = 1'b1;
				end
			default:
				;
		endcase
	end
	initial _sv2v_0 = 0;
endmodule

module csa (
	a,
	b,
	cin,
	s,
	cout
);
	parameter N = 64;
	input [N - 1:0] a;
	input [N - 1:0] b;
	input [N - 1:0] cin;
	output wire [N - 1:0] s;
	output wire [N - 1:0] cout;
	wire [N - 1:0] w_xor_ab = a ^ b;
	assign s = w_xor_ab ^ cin;
	assign cout = (a & b) | (cin & w_xor_ab);
endmodule

module find_first_set (
	in,
	y
);
	reg _sv2v_0;
	parameter LG_N = 2;
	localparam N = 1 << LG_N;
	localparam N2 = 1 << (LG_N - 1);
	input wire [N - 1:0] in;
	output reg [LG_N:0] y;
	wire [LG_N - 1:0] t0;
	wire [LG_N - 1:0] t1;
	wire lo_z = in[N2 - 1:0] == 'd0;
	wire hi_z = in[N - 1:N2] == 'd0;
	generate
		if (LG_N == 2) begin : genblk1
			always @(*) begin
				if (_sv2v_0)
					;
				y = 3'b111;
				casez (in)
					4'b0001: y = 3'd0;
					4'b001z: y = 3'd1;
					4'b01zz: y = 3'd2;
					4'b1zzz: y = 3'd3;
					default: y = 3'b111;
				endcase
			end
		end
		else begin : genblk1
			find_first_set #(.LG_N(LG_N - 1)) f0(
				.in(in[N2 - 1:0]),
				.y(t0)
			);
			find_first_set #(.LG_N(LG_N - 1)) f1(
				.in(in[N - 1:N2]),
				.y(t1)
			);
			always @(*) begin
				if (_sv2v_0)
					;
				y = N;
				if (lo_z && hi_z)
					y = N;
				else if (!hi_z)
					y = N2 + t1;
				else if (!lo_z)
					y = {1'b0, t0};
			end
		end
	endgenerate
	initial _sv2v_0 = 0;
endmodule

module exec (
	clk,
	reset,
	putchar_fifo_out,
	putchar_fifo_empty,
	putchar_fifo_pop,
	putchar_fifo_wptr,
	putchar_fifo_rptr,
	cause,
	epc,
	tval,
	irq,
	mie,
	mip,
	mideleg,
	mstatus,
	exc_pc,
	update_csr_exc,
	priv,
	priv_update,
	page_table_root,
	paging_active,
	clear_tlb,
	mode64,
	retire,
	retire_two,
	divide_ready,
	ds_done,
	mem_dq_clr,
	restart_complete,
	uq_wait,
	mq_wait,
	uq_full,
	uq_next_full,
	uq_uop,
	uq_uop_two,
	uq_push,
	uq_push_two,
	complete_bundle_1,
	complete_valid_1,
	complete_bundle_2,
	complete_valid_2,
	mem_req,
	mem_req_valid,
	mem_req_ack,
	core_store_data_valid,
	core_store_data,
	core_store_data_ack,
	core_store_data_ptr,
	core_store_data_ptr_valid,
	mem_rsp_dst_ptr,
	mem_rsp_dst_valid,
	mem_rsp_load_data,
	mtimecmp,
	mtimecmp_val,
	branch_valid,
	branch_fault,
	counters
);
	reg _sv2v_0;
	input wire clk;
	input wire reset;
	output wire [7:0] putchar_fifo_out;
	output wire putchar_fifo_empty;
	input wire putchar_fifo_pop;
	output wire [3:0] putchar_fifo_wptr;
	output wire [3:0] putchar_fifo_rptr;
	output wire [1:0] priv;
	output wire priv_update;
	input wire [4:0] cause;
	input wire [63:0] epc;
	input wire [63:0] tval;
	input wire irq;
	output wire [63:0] mip;
	output wire [63:0] mie;
	output wire [63:0] mideleg;
	output wire [63:0] mstatus;
	output reg [63:0] exc_pc;
	input wire update_csr_exc;
	output wire [63:0] page_table_root;
	output wire paging_active;
	output wire clear_tlb;
	input wire mode64;
	input wire retire;
	input wire retire_two;
	output wire divide_ready;
	input wire ds_done;
	input wire mem_dq_clr;
	input wire restart_complete;
	localparam N_ROB_ENTRIES = 32;
	output wire [31:0] uq_wait;
	output wire [31:0] mq_wait;
	output reg uq_full;
	output reg uq_next_full;
	input wire [251:0] uq_uop;
	input wire [251:0] uq_uop_two;
	input wire uq_push;
	input wire uq_push_two;
	output reg [141:0] complete_bundle_1;
	output reg complete_valid_1;
	output reg [141:0] complete_bundle_2;
	output reg complete_valid_2;
	output wire [230:0] mem_req;
	output wire mem_req_valid;
	input wire mem_req_ack;
	output wire core_store_data_valid;
	output reg [68:0] core_store_data;
	input wire core_store_data_ack;
	output reg [4:0] core_store_data_ptr;
	output reg core_store_data_ptr_valid;
	input wire [6:0] mem_rsp_dst_ptr;
	input wire mem_rsp_dst_valid;
	input wire [63:0] mem_rsp_load_data;
	input wire [63:0] mtimecmp;
	input wire mtimecmp_val;
	input wire branch_valid;
	input wire branch_fault;
	input wire [639:0] counters;
	localparam N_INT_SCHED_ENTRIES = 4;
	localparam N_MEM_SCHED_ENTRIES = 4;
	localparam N_MQ_ENTRIES = 4;
	localparam N_MDQ_ENTRIES = 8;
	localparam N_INT_PRF_ENTRIES = 128;
	localparam N_UQ_ENTRIES = 16;
	localparam N_MEM_UQ_ENTRIES = 8;
	localparam N_MEM_DQ_ENTRIES = 8;
	reg [127:0] r_prf_inflight;
	reg t_wr_int_prf;
	reg t_wr_int_prf2;
	reg r_clear_tlb;
	reg t_clear_tlb;
	reg [1:0] r_priv;
	reg [1:0] n_priv;
	assign priv = r_priv;
	assign clear_tlb = r_clear_tlb;
	reg t_take_br;
	reg t_take_br2;
	reg t_mispred_br;
	reg t_mispred_br2;
	reg t_alu_valid;
	reg t_alu_valid2;
	reg t_got_break;
	reg [230:0] r_mem_q [3:0];
	reg [2:0] r_mq_head_ptr;
	reg [2:0] n_mq_head_ptr;
	reg [2:0] r_mq_tail_ptr;
	reg [2:0] n_mq_tail_ptr;
	reg [2:0] r_mq_next_tail_ptr;
	reg [2:0] n_mq_next_tail_ptr;
	reg [230:0] t_mem_tail;
	reg [230:0] t_mem_head;
	reg mem_q_full;
	reg mem_q_next_full;
	reg mem_q_empty;
	reg [68:0] r_mdq [7:0];
	wire [68:0] t_mdq_tail;
	wire [68:0] t_mdq_head;
	reg [3:0] r_mdq_head_ptr;
	reg [3:0] n_mdq_head_ptr;
	reg [3:0] r_mdq_tail_ptr;
	reg [3:0] n_mdq_tail_ptr;
	reg [3:0] r_mdq_next_tail_ptr;
	reg [3:0] n_mdq_next_tail_ptr;
	reg mem_mdq_full;
	reg mem_mdq_next_full;
	reg mem_mdq_empty;
	wire [6:0] w_mul_prf_ptr;
	reg [6:0] r_mul_prf_ptr;
	reg r_mul_complete;
	wire [6:0] w_div_prf_ptr;
	reg [6:0] r_div_prf_ptr;
	reg r_div_complete;
	wire w_pop_uq;
	wire w_pop_uq2;
	wire w_alloc_uq;
	wire w_alloc_uq2;
	wire w_uq_swizzle;
	reg t_pop_mem_uq;
	reg t_pop_mem_dq;
	reg r_mem_ready;
	reg r_dq_ready;
	reg r_paging_active;
	localparam E_BITS = 48;
	localparam HI_EBITS = 32;
	reg [63:0] t_result;
	reg [63:0] t_result2;
	wire [62:0] w_zf = 'd0;
	reg [63:0] t_pc;
	reg [63:0] t_pc_2;
	wire t_srcs_rdy;
	reg [3:0] r_alu_sched_valid;
	reg [3:0] r_alu_sched_valid2;
	wire [2:0] t_alu_sched_alloc_ptr;
	wire [2:0] t_alu_sched_alloc_ptr2;
	reg [3:0] t_alu_alloc_entry;
	reg [3:0] t_alu_select_entry;
	reg [3:0] t_alu_alloc_entry2;
	reg [3:0] t_alu_select_entry2;
	reg [251:0] r_alu_sched_uops [3:0];
	reg [251:0] t_picked_uop;
	reg [251:0] r_alu_sched_uops2 [3:0];
	reg [251:0] t_picked_uop2;
	reg [3:0] t_alu_entry_rdy;
	reg [3:0] t_alu_entry_rdy2;
	wire [2:0] t_alu_sched_select_ptr;
	wire [2:0] t_alu_sched_select_ptr2;
	reg [3:0] r_alu_srcA_rdy;
	reg [3:0] r_alu_srcB_rdy;
	reg [3:0] r_alu_srcA_rdy2;
	reg [3:0] r_alu_srcB_rdy2;
	reg [3:0] t_alu_srcA_match;
	reg [3:0] t_alu_srcB_match;
	reg [3:0] t_alu_srcA_match2;
	reg [3:0] t_alu_srcB_match2;
	reg t_alu_alloc_srcA_match;
	reg t_alu_alloc_srcB_match;
	reg t_alu_alloc_srcA_match2;
	reg t_alu_alloc_srcB_match2;
	wire [3:0] w_alu_sched_oldest_ready;
	wire [3:0] w_alu_sched_oldest_ready2;
	reg [3:0] t_alu_sched_mask_valid;
	reg [3:0] t_alu_sched_mask_valid2;
	reg [3:0] r_alu_sched_matrix [3:0];
	reg [3:0] r_alu_sched_matrix2 [3:0];
	reg [3:0] r_mem_sched_valid;
	reg [3:0] r_mem_sched_store;
	wire [2:0] t_mem_sched_alloc_ptr;
	reg [3:0] t_mem_alloc_entry;
	reg [3:0] t_mem_select_entry;
	reg [251:0] r_mem_sched_uops [3:0];
	reg [251:0] t_picked_mem_uop;
	reg [3:0] t_mem_entry_reg_rdy;
	wire [2:0] t_mem_sched_select_ptr;
	reg [3:0] r_mem_srcA_rdy;
	wire [3:0] r_mem_srcB_rdy;
	reg [3:0] t_mem_srcA_match;
	wire [3:0] t_mem_srcB_match;
	reg t_mem_alloc_srcA_match;
	wire t_mem_alloc_srcB_match;
	wire [3:0] w_mem_sched_oldest_ready;
	reg [3:0] t_mem_sched_mask_valid;
	reg [3:0] r_mem_sched_matrix [3:0];
	wire [63:0] w_srcA;
	wire [63:0] w_srcB;
	reg [63:0] t_srcA_2;
	reg [63:0] t_srcB_2;
	wire [63:0] w_srcA_2;
	wire [63:0] w_srcB_2;
	wire [63:0] w_mem_srcA;
	wire [63:0] w_mem_srcB;
	reg [63:0] r_mem_result;
	reg [63:0] r_int_result;
	reg [63:0] r_int_result2;
	reg r_fwd_int_srcA;
	reg r_fwd_int_srcB;
	reg r_fwd_int2_srcA;
	reg r_fwd_int2_srcB;
	reg r_fwd_int_srcA2;
	reg r_fwd_int_srcB2;
	reg r_fwd_int2_srcA2;
	reg r_fwd_int2_srcB2;
	reg r_fwd_mul_srcA;
	reg r_fwd_mul_srcB;
	reg r_fwd_mul_srcA2;
	reg r_fwd_mul_srcB2;
	reg r_fwd_mem_srcA;
	reg r_fwd_mem_srcB;
	reg r_fwd_mem_srcA2;
	reg r_fwd_mem_srcB2;
	reg t_fwd_int_mem_srcA;
	reg t_fwd_int_mem_srcB;
	reg t_fwd_int2_mem_srcA;
	reg t_fwd_int2_mem_srcB;
	reg t_fwd_mem_mem_srcA;
	reg t_fwd_mem_mem_srcB;
	reg r_fwd_int_mem_srcA;
	reg r_fwd_int_mem_srcB;
	reg r_fwd_int2_mem_srcA;
	reg r_fwd_int2_mem_srcB;
	reg r_fwd_mem_mem_srcA;
	reg r_fwd_mem_mem_srcB;
	reg [63:0] t_srcA;
	reg [63:0] t_srcB;
	reg [63:0] t_mem_srcA;
	reg [63:0] t_mem_srcB;
	reg t_has_cause;
	reg [4:0] t_cause;
	reg t_wr_csr_en;
	reg t_rd_csr_en;
	reg [63:0] t_rd_csr;
	reg [63:0] t_wr_csr;
	reg t_wr_priv;
	reg [1:0] t_priv;
	reg [63:0] r_stvec;
	reg [63:0] r_sscratch;
	reg [63:0] r_sepc;
	reg [63:0] r_stval;
	reg [63:0] r_satp;
	reg [63:0] r_mstatus;
	reg [63:0] r_mideleg;
	reg [63:0] r_medeleg;
	reg [63:0] r_mcounteren;
	reg [63:0] r_mie;
	reg [63:0] r_mscratch;
	reg [63:0] r_mepc;
	reg [63:0] r_mtvec;
	reg [63:0] r_mtval;
	reg [63:0] r_misa;
	reg [63:0] r_mip;
	reg [63:0] r_scounteren;
	reg [63:0] r_mcause;
	reg [63:0] r_scause;
	reg [63:0] r_pmpaddr0;
	reg [63:0] r_pmpaddr1;
	reg [63:0] r_pmpaddr2;
	reg [63:0] r_pmpaddr3;
	reg [63:0] r_pmpcfg0;
	reg t_push_putchar;
	wire [1:0] w_mpp = r_mstatus[12:11];
	wire w_spp = r_mstatus[8];
	wire w_mpie = r_mstatus[7];
	wire w_spie = r_mstatus[5];
	assign mie = r_mie;
	assign mip = r_mip;
	assign mideleg = r_mideleg;
	assign mstatus = r_mstatus;
	reg t_signed_shift;
	reg t_left_shift;
	reg t_zero_shift_upper;
	reg [5:0] t_shift_amt;
	wire [63:0] w_shifter_out;
	reg t_start_mul;
	reg t_is_mulw;
	reg t_signed_mul;
	wire t_mul_complete;
	wire [63:0] t_mul_result;
	reg [63:0] r_mul_result;
	wire [4:0] t_rob_ptr_out;
	reg [66:0] r_wb_bitvec;
	reg [66:0] n_wb_bitvec;
	wire t_div_ready;
	reg t_signed_div;
	reg t_is_rem;
	reg t_start_div32;
	reg t_start_div64;
	wire [4:0] t_div_rob_ptr;
	wire [63:0] t_div_result;
	wire t_div_complete;
	reg [31:0] r_uq_wait;
	reg [31:0] r_mq_wait;
	reg [251:0] r_uq [0:15];
	reg [251:0] uq;
	reg [251:0] uq2;
	reg [251:0] int_uop;
	reg [251:0] int_uop2;
	reg [251:0] t_uq;
	reg [251:0] t_uq2;
	reg r_start_int2;
	reg r_start_int;
	wire t_uq_read;
	reg t_uq_empty;
	reg t_uq_full;
	reg t_uq_next_full;
	reg t_uq_next_empty;
	reg [4:0] r_uq_head_ptr;
	reg [4:0] n_uq_head_ptr;
	reg [4:0] r_uq_tail_ptr;
	reg [4:0] n_uq_tail_ptr;
	reg [4:0] r_uq_next_head_ptr;
	reg [4:0] n_uq_next_head_ptr;
	reg [4:0] r_uq_next_tail_ptr;
	reg [4:0] n_uq_next_tail_ptr;
	reg [251:0] r_mem_uq [0:7];
	reg [251:0] t_mem_uq;
	wire t_mem_uq_read;
	reg t_mem_uq_empty;
	reg t_mem_uq_full;
	reg t_mem_uq_next_full;
	reg [3:0] r_mem_uq_head_ptr;
	reg [3:0] n_mem_uq_head_ptr;
	reg [3:0] r_mem_uq_tail_ptr;
	reg [3:0] n_mem_uq_tail_ptr;
	reg [3:0] r_mem_uq_next_head_ptr;
	reg [3:0] n_mem_uq_next_head_ptr;
	reg [3:0] r_mem_uq_next_tail_ptr;
	reg [3:0] n_mem_uq_next_tail_ptr;
	reg [11:0] r_mem_dq [0:7];
	reg [11:0] t_dq0;
	reg [11:0] t_dq1;
	reg [11:0] t_mem_dq;
	reg [11:0] mem_dq;
	reg [68:0] t_core_store_data;
	wire t_mem_dq_read;
	reg t_mem_dq_empty;
	reg t_mem_dq_full;
	reg t_mem_dq_next_full;
	reg [3:0] r_mem_dq_head_ptr;
	reg [3:0] n_mem_dq_head_ptr;
	reg [3:0] r_mem_dq_tail_ptr;
	reg [3:0] n_mem_dq_tail_ptr;
	reg [3:0] r_mem_dq_next_head_ptr;
	reg [3:0] n_mem_dq_next_head_ptr;
	reg [3:0] r_mem_dq_next_tail_ptr;
	reg [3:0] n_mem_dq_next_tail_ptr;
	reg t_push_two_mem;
	reg t_push_two_int;
	reg t_push_one_mem;
	reg t_push_one_int;
	reg t_push_two_dq;
	reg t_push_one_dq;
	reg t_flash_clear;
	always @(*) begin
		if (_sv2v_0)
			;
		t_flash_clear = ds_done;
	end
	always @(*) begin
		if (_sv2v_0)
			;
		uq_full = (t_uq_full | t_mem_uq_full) | t_mem_dq_full;
		uq_next_full = (t_uq_next_full | t_mem_uq_next_full) | t_mem_dq_next_full;
	end
	always @(posedge clk)
		if (reset | t_flash_clear) begin
			r_uq_head_ptr <= 'd0;
			r_uq_tail_ptr <= 'd0;
			r_uq_next_head_ptr <= 'd1;
			r_uq_next_tail_ptr <= 'd1;
		end
		else begin
			r_uq_head_ptr <= n_uq_head_ptr;
			r_uq_tail_ptr <= n_uq_tail_ptr;
			r_uq_next_head_ptr <= n_uq_next_head_ptr;
			r_uq_next_tail_ptr <= n_uq_next_tail_ptr;
		end
	always @(posedge clk)
		if (reset | t_flash_clear) begin
			r_mem_uq_head_ptr <= 'd0;
			r_mem_uq_tail_ptr <= 'd0;
			r_mem_uq_next_head_ptr <= 'd1;
			r_mem_uq_next_tail_ptr <= 'd1;
		end
		else begin
			r_mem_uq_head_ptr <= n_mem_uq_head_ptr;
			r_mem_uq_tail_ptr <= n_mem_uq_tail_ptr;
			r_mem_uq_next_head_ptr <= n_mem_uq_next_head_ptr;
			r_mem_uq_next_tail_ptr <= n_mem_uq_next_tail_ptr;
		end
	always @(posedge clk)
		if (reset | mem_dq_clr) begin
			r_mem_dq_head_ptr <= 'd0;
			r_mem_dq_tail_ptr <= 'd0;
			r_mem_dq_next_head_ptr <= 'd1;
			r_mem_dq_next_tail_ptr <= 'd1;
		end
		else begin
			r_mem_dq_head_ptr <= n_mem_dq_head_ptr;
			r_mem_dq_tail_ptr <= n_mem_dq_tail_ptr;
			r_mem_dq_next_head_ptr <= n_mem_dq_next_head_ptr;
			r_mem_dq_next_tail_ptr <= n_mem_dq_next_tail_ptr;
		end
	always @(*) begin
		if (_sv2v_0)
			;
		n_mem_uq_head_ptr = r_mem_uq_head_ptr;
		n_mem_uq_tail_ptr = r_mem_uq_tail_ptr;
		n_mem_uq_next_head_ptr = r_mem_uq_next_head_ptr;
		n_mem_uq_next_tail_ptr = r_mem_uq_next_tail_ptr;
		n_mem_dq_head_ptr = r_mem_dq_head_ptr;
		n_mem_dq_tail_ptr = r_mem_dq_tail_ptr;
		n_mem_dq_next_head_ptr = r_mem_dq_next_head_ptr;
		n_mem_dq_next_tail_ptr = r_mem_dq_next_tail_ptr;
		t_mem_uq_empty = r_mem_uq_head_ptr == r_mem_uq_tail_ptr;
		t_mem_uq_full = (r_mem_uq_head_ptr != r_mem_uq_tail_ptr) && (r_mem_uq_head_ptr[2:0] == r_mem_uq_tail_ptr[2:0]);
		t_mem_uq_next_full = (r_mem_uq_head_ptr != r_mem_uq_next_tail_ptr) && (r_mem_uq_head_ptr[2:0] == r_mem_uq_next_tail_ptr[2:0]);
		t_mem_dq_empty = r_mem_dq_head_ptr == r_mem_dq_tail_ptr;
		t_mem_dq_full = (r_mem_dq_head_ptr != r_mem_dq_tail_ptr) && (r_mem_dq_head_ptr[2:0] == r_mem_dq_tail_ptr[2:0]);
		t_mem_dq_next_full = (r_mem_dq_head_ptr != r_mem_dq_next_tail_ptr) && (r_mem_dq_head_ptr[2:0] == r_mem_dq_next_tail_ptr[2:0]);
		t_mem_uq = r_mem_uq[r_mem_uq_head_ptr[2:0]];
		t_mem_dq = r_mem_dq[r_mem_dq_head_ptr[2:0]];
		t_push_two_mem = ((uq_push && uq_push_two) && uq_uop[18]) && uq_uop_two[18];
		t_push_one_mem = ((uq_push && uq_uop[18]) || (uq_push_two && uq_uop_two[18])) && !t_push_two_mem;
		t_push_two_dq = ((((uq_push && uq_push_two) && uq_uop[18]) && uq_uop[229]) && uq_uop_two[18]) && uq_uop_two[229];
		t_push_one_dq = ((uq_push_two && uq_uop_two[18]) && uq_uop_two[229]) || ((uq_push && uq_uop[18]) && uq_uop[229]);
		if (t_push_two_dq) begin
			n_mem_dq_tail_ptr = r_mem_dq_tail_ptr + 'd2;
			n_mem_dq_next_tail_ptr = r_mem_dq_next_tail_ptr + 'd2;
		end
		else if (t_push_one_dq) begin
			n_mem_dq_tail_ptr = r_mem_dq_tail_ptr + 'd1;
			n_mem_dq_next_tail_ptr = r_mem_dq_next_tail_ptr + 'd1;
		end
		if (t_push_two_mem) begin
			n_mem_uq_tail_ptr = r_mem_uq_tail_ptr + 'd2;
			n_mem_uq_next_tail_ptr = r_mem_uq_next_tail_ptr + 'd2;
		end
		else if ((uq_push_two && uq_uop_two[18]) || (uq_push && uq_uop[18])) begin
			n_mem_uq_tail_ptr = r_mem_uq_tail_ptr + 'd1;
			n_mem_uq_next_tail_ptr = r_mem_uq_next_tail_ptr + 'd1;
		end
		if (t_pop_mem_uq)
			n_mem_uq_head_ptr = r_mem_uq_head_ptr + 'd1;
		if (t_pop_mem_dq)
			n_mem_dq_head_ptr = r_mem_dq_head_ptr + 'd1;
	end
	always @(posedge clk) mem_dq <= t_mem_dq;
	reg [251:0] mem_uop;
	always @(posedge clk)
		if (reset) begin
			r_mq_wait <= 'd0;
			r_uq_wait <= 'd0;
		end
		else if (restart_complete) begin
			r_mq_wait <= 'd0;
			r_uq_wait <= 'd0;
		end
		else begin
			if (t_push_two_mem) begin
				r_mq_wait[uq_uop_two[28-:5]] <= 1'b1;
				r_mq_wait[uq_uop[28-:5]] <= 1'b1;
			end
			else if (t_push_one_mem)
				r_mq_wait[(uq_uop[18] ? uq_uop[28-:5] : uq_uop_two[28-:5])] <= 1'b1;
			if (r_mem_ready)
				r_mq_wait[mem_uop[28-:5]] <= 1'b0;
			if (t_push_two_int) begin
				r_uq_wait[uq_uop[28-:5]] <= 1'b1;
				r_uq_wait[uq_uop_two[28-:5]] <= 1'b1;
			end
			else if (t_push_one_int)
				r_uq_wait[(uq_uop[20] ? uq_uop[28-:5] : uq_uop_two[28-:5])] <= 1'b1;
			if (r_start_int)
				r_uq_wait[int_uop[28-:5]] <= 1'b0;
		end
	always @(posedge clk)
		if (t_push_two_mem) begin
			r_mem_uq[r_mem_uq_next_tail_ptr[2:0]] <= uq_uop_two;
			r_mem_uq[r_mem_uq_tail_ptr[2:0]] <= uq_uop;
		end
		else if (t_push_one_mem)
			r_mem_uq[r_mem_uq_tail_ptr[2:0]] <= (uq_uop[18] ? uq_uop : uq_uop_two);
	always @(*) begin
		if (_sv2v_0)
			;
		t_dq0[11-:5] = uq_uop[28-:5];
		t_dq0[6-:7] = uq_uop[236-:7];
		t_dq1[11-:5] = uq_uop_two[28-:5];
		t_dq1[6-:7] = uq_uop_two[236-:7];
	end
	always @(posedge clk)
		if (t_push_two_dq) begin
			r_mem_dq[r_mem_dq_next_tail_ptr[2:0]] <= t_dq1;
			r_mem_dq[r_mem_dq_tail_ptr[2:0]] <= t_dq0;
		end
		else if (t_push_one_dq)
			r_mem_dq[r_mem_dq_tail_ptr[2:0]] <= (uq_uop[18] && uq_uop[229] ? t_dq0 : t_dq1);
	always @(*) begin
		if (_sv2v_0)
			;
		t_uq = r_uq[r_uq_head_ptr[3:0]];
		t_uq2 = r_uq[r_uq_next_head_ptr[3:0]];
	end
	wire w_alu_sched_avail = (&r_alu_sched_valid == 1'b0) & (t_flash_clear == 1'b0);
	wire w_alu_sched_avail2 = (&r_alu_sched_valid2 == 1'b0) & (t_flash_clear == 1'b0);
	wire w_uop1_on_sched1 = w_alu_sched_avail & (t_uq_empty == 1'b0);
	wire w_uop1_on_sched2 = (w_alu_sched_avail2 & (t_uq_empty == 1'b0)) & t_uq[0];
	wire w_sched_two_uops = (((w_alu_sched_avail & w_alu_sched_avail2) & (t_uq_empty == 1'b0)) & (t_uq_next_empty == 1'b0)) & (t_uq[0] | t_uq2[0]);
	assign w_pop_uq = (w_sched_two_uops | w_uop1_on_sched2) | w_uop1_on_sched1;
	assign w_pop_uq2 = w_sched_two_uops;
	assign w_alloc_uq = w_sched_two_uops | (((w_sched_two_uops == 1'b0) & (w_uop1_on_sched2 == 1'b0)) & w_uop1_on_sched1);
	assign w_alloc_uq2 = w_sched_two_uops | ((w_sched_two_uops == 1'b0) & w_uop1_on_sched2);
	assign w_uq_swizzle = ((w_sched_two_uops & t_uq[0]) & !t_uq2[0]) | ((w_sched_two_uops == 1'b0) & w_uop1_on_sched2);
	always @(*) begin
		if (_sv2v_0)
			;
		n_uq_head_ptr = r_uq_head_ptr;
		n_uq_tail_ptr = r_uq_tail_ptr;
		n_uq_next_head_ptr = r_uq_next_head_ptr;
		n_uq_next_tail_ptr = r_uq_next_tail_ptr;
		t_uq_empty = r_uq_head_ptr == r_uq_tail_ptr;
		t_uq_next_empty = r_uq_next_head_ptr == r_uq_tail_ptr;
		t_uq_full = (r_uq_head_ptr != r_uq_tail_ptr) && (r_uq_head_ptr[3:0] == r_uq_tail_ptr[3:0]);
		t_uq_next_full = (r_uq_head_ptr != r_uq_next_tail_ptr) && (r_uq_head_ptr[3:0] == r_uq_next_tail_ptr[3:0]);
		t_push_two_int = ((uq_push && uq_push_two) && uq_uop[20]) && uq_uop_two[20];
		t_push_one_int = ((uq_push && uq_uop[20]) || (uq_push_two && uq_uop_two[20])) && !t_push_two_int;
		uq = (w_uq_swizzle ? t_uq2 : t_uq);
		uq2 = (w_uq_swizzle ? t_uq : t_uq2);
		if (t_push_two_int) begin
			n_uq_tail_ptr = r_uq_tail_ptr + 'd2;
			n_uq_next_tail_ptr = r_uq_next_tail_ptr + 'd2;
		end
		else if ((uq_push_two && uq_uop_two[20]) || (uq_push && uq_uop[20])) begin
			n_uq_tail_ptr = r_uq_tail_ptr + 'd1;
			n_uq_next_tail_ptr = r_uq_next_tail_ptr + 'd1;
		end
		if (w_pop_uq2) begin
			n_uq_next_head_ptr = r_uq_next_head_ptr + 'd2;
			n_uq_head_ptr = r_uq_head_ptr + 'd2;
		end
		else if (w_pop_uq) begin
			n_uq_head_ptr = r_uq_head_ptr + 'd1;
			n_uq_next_head_ptr = r_uq_next_head_ptr + 'd1;
		end
	end
	always @(posedge clk)
		if (t_push_two_int) begin
			r_uq[r_uq_tail_ptr[3:0]] <= uq_uop;
			r_uq[r_uq_next_tail_ptr[3:0]] <= uq_uop_two;
		end
		else if (t_push_one_int)
			r_uq[r_uq_tail_ptr[3:0]] <= (uq_uop[20] ? uq_uop : uq_uop_two);
	reg [63:0] r_cycle;
	reg [63:0] r_retired_insns;
	reg [63:0] r_branches;
	reg [63:0] r_branch_faults;
	reg [63:0] r_mtime;
	reg [63:0] r_mtimecmp;
	wire w_mtip = r_cycle >= r_mtimecmp;
	always @(posedge clk)
		if (reset)
			r_mtimecmp <= 64'd0;
		else if (mtimecmp_val)
			r_mtimecmp <= mtimecmp;
	always @(posedge clk) begin
		r_cycle <= (reset ? 'd0 : r_cycle + 'd1);
		r_branches <= (reset ? 'd0 : (branch_valid ? r_branches + 'd1 : r_branches));
		r_branch_faults <= (reset ? 'd0 : (branch_fault ? r_branch_faults + 'd1 : r_branch_faults));
	end
	always @(posedge clk)
		if (reset)
			r_retired_insns <= 'd0;
		else if (retire_two)
			r_retired_insns <= r_retired_insns + 'd2;
		else if (retire)
			r_retired_insns <= r_retired_insns + 'd1;
	always @(posedge clk)
		if (reset)
			r_wb_bitvec <= 'd0;
		else
			r_wb_bitvec <= n_wb_bitvec;
	always @(*) begin
		if (_sv2v_0)
			;
		begin : sv2v_autoblock_1
			integer i;
			for (i = 65; i > -1; i = i - 1)
				n_wb_bitvec[i] = r_wb_bitvec[i + 1];
		end
		n_wb_bitvec[66] = t_start_div64 & r_start_int;
		if (t_start_mul & r_start_int)
			n_wb_bitvec[3] = 1'b1;
	end
	always @(*) begin
		if (_sv2v_0)
			;
		t_srcA = (r_fwd_int_srcA ? r_int_result : (r_fwd_int2_srcA ? r_int_result2 : (r_fwd_mem_srcA ? r_mem_result : (r_fwd_mul_srcA ? r_mul_result : w_srcA))));
		t_srcB = (r_fwd_int_srcB ? r_int_result : (r_fwd_int2_srcB ? r_int_result2 : (r_fwd_mem_srcB ? r_mem_result : (r_fwd_mul_srcB ? r_mul_result : w_srcB))));
		t_srcA_2 = (r_fwd_int_srcA2 ? r_int_result : (r_fwd_int2_srcA2 ? r_int_result2 : (r_fwd_mem_srcA2 ? r_mem_result : (r_fwd_mul_srcA2 ? r_mul_result : w_srcA_2))));
		t_srcB_2 = (r_fwd_int_srcB2 ? r_int_result : (r_fwd_int2_srcB2 ? r_int_result2 : (r_fwd_mem_srcB2 ? r_mem_result : (r_fwd_mul_srcB2 ? r_mul_result : w_srcB_2))));
		t_mem_srcA = (r_fwd_int_mem_srcA ? r_int_result : (r_fwd_mem_mem_srcA ? r_mem_result : (r_fwd_int2_mem_srcA ? r_int_result2 : w_mem_srcA)));
		t_mem_srcB = (r_fwd_int_mem_srcB ? r_int_result : (r_fwd_mem_mem_srcB ? r_mem_result : (r_fwd_int2_mem_srcB ? r_int_result2 : w_mem_srcB)));
	end
	find_first_set #(2) ffs_int_sched_alloc(
		.in(~r_alu_sched_valid),
		.y(t_alu_sched_alloc_ptr)
	);
	find_first_set #(2) ffs_int_sched_select(
		.in(w_alu_sched_oldest_ready),
		.y(t_alu_sched_select_ptr)
	);
	find_first_set #(2) ffs_int_sched_alloc2(
		.in(~r_alu_sched_valid2),
		.y(t_alu_sched_alloc_ptr2)
	);
	find_first_set #(2) ffs_int_sched_select2(
		.in(w_alu_sched_oldest_ready2),
		.y(t_alu_sched_select_ptr2)
	);
	always @(*) begin
		if (_sv2v_0)
			;
		t_alu_alloc_entry = 'd0;
		t_alu_select_entry = 'd0;
		if (w_alloc_uq)
			t_alu_alloc_entry[t_alu_sched_alloc_ptr[1:0]] = 1'b1;
		if (t_alu_entry_rdy != 'd0)
			t_alu_select_entry[t_alu_sched_select_ptr[1:0]] = 1'b1;
	end
	always @(*) begin
		if (_sv2v_0)
			;
		t_alu_alloc_entry2 = 'd0;
		t_alu_select_entry2 = 'd0;
		if (w_alloc_uq2)
			t_alu_alloc_entry2[t_alu_sched_alloc_ptr2[1:0]] = 1'b1;
		if (t_alu_entry_rdy2 != 'd0)
			t_alu_select_entry2[t_alu_sched_select_ptr2[1:0]] = 1'b1;
	end
	always @(*) begin
		if (_sv2v_0)
			;
		t_picked_uop = r_alu_sched_uops[t_alu_sched_select_ptr[1:0]];
	end
	always @(*) begin
		if (_sv2v_0)
			;
		t_picked_uop2 = r_alu_sched_uops2[t_alu_sched_select_ptr2[1:0]];
	end
	always @(posedge clk) int_uop <= t_picked_uop;
	always @(posedge clk) r_start_int <= (reset ? 1'b0 : (t_alu_entry_rdy != 'd0) & !ds_done);
	always @(posedge clk) int_uop2 <= t_picked_uop2;
	always @(posedge clk) r_start_int2 <= (reset ? 1'b0 : (t_alu_entry_rdy2 != 'd0) & !ds_done);
	always @(*) begin
		if (_sv2v_0)
			;
		t_alu_alloc_srcA_match = uq[237] && ((((mem_rsp_dst_valid & (mem_rsp_dst_ptr == uq[244-:7])) || (t_mul_complete && (w_mul_prf_ptr == uq[244-:7]))) || ((r_start_int2 && t_wr_int_prf2) && (int_uop2[228-:7] == uq[244-:7]))) || (r_start_int && (t_wr_int_prf & (int_uop[228-:7] == uq[244-:7]))));
		t_alu_alloc_srcB_match = uq[229] && ((((mem_rsp_dst_valid & (mem_rsp_dst_ptr == uq[236-:7])) || (t_mul_complete && (w_mul_prf_ptr == uq[236-:7]))) || ((r_start_int2 && t_wr_int_prf2) && (int_uop2[228-:7] == uq[236-:7]))) || (r_start_int && (t_wr_int_prf & (int_uop[228-:7] == uq[236-:7]))));
		t_alu_alloc_srcA_match2 = uq2[237] && ((((mem_rsp_dst_valid & (mem_rsp_dst_ptr == uq2[244-:7])) || (t_mul_complete && (w_mul_prf_ptr == uq2[244-:7]))) || ((r_start_int2 && t_wr_int_prf2) && (int_uop2[228-:7] == uq2[244-:7]))) || (r_start_int && (t_wr_int_prf & (int_uop[228-:7] == uq2[244-:7]))));
		t_alu_alloc_srcB_match2 = uq2[229] && ((((mem_rsp_dst_valid & (mem_rsp_dst_ptr == uq2[236-:7])) || (t_mul_complete && (w_mul_prf_ptr == uq2[236-:7]))) || ((r_start_int2 && t_wr_int_prf2) && (int_uop2[228-:7] == uq2[236-:7]))) || (r_start_int && (t_wr_int_prf & (int_uop[228-:7] == uq2[236-:7]))));
	end
	always @(*) begin
		if (_sv2v_0)
			;
		t_alu_sched_mask_valid = r_alu_sched_valid & ~t_alu_select_entry;
		t_alu_sched_mask_valid2 = r_alu_sched_valid2 & ~t_alu_select_entry2;
	end
	genvar _gv_i_1;
	generate
		for (_gv_i_1 = 0; _gv_i_1 < N_INT_SCHED_ENTRIES; _gv_i_1 = _gv_i_1 + 1) begin : genblk1
			localparam i = _gv_i_1;
			assign w_alu_sched_oldest_ready[i] = t_alu_entry_rdy[i] & ~(|(t_alu_entry_rdy & r_alu_sched_matrix[i]));
			always @(posedge clk)
				if (reset || t_flash_clear)
					r_alu_sched_matrix[i] <= 'd0;
				else if (t_alu_alloc_entry[i])
					r_alu_sched_matrix[i] <= t_alu_sched_mask_valid;
				else if (t_alu_entry_rdy != 'd0)
					r_alu_sched_matrix[i] <= r_alu_sched_matrix[i] & ~t_alu_select_entry;
		end
	endgenerate
	genvar _gv_i_2;
	generate
		for (_gv_i_2 = 0; _gv_i_2 < N_INT_SCHED_ENTRIES; _gv_i_2 = _gv_i_2 + 1) begin : genblk2
			localparam i = _gv_i_2;
			assign w_alu_sched_oldest_ready2[i] = t_alu_entry_rdy2[i] & ~(|(t_alu_entry_rdy2 & r_alu_sched_matrix2[i]));
			always @(posedge clk)
				if (reset || t_flash_clear)
					r_alu_sched_matrix2[i] <= 'd0;
				else if (t_alu_alloc_entry2[i])
					r_alu_sched_matrix2[i] <= t_alu_sched_mask_valid2;
				else if (t_alu_entry_rdy2 != 'd0)
					r_alu_sched_matrix2[i] <= r_alu_sched_matrix2[i] & ~t_alu_select_entry2;
		end
	endgenerate
	genvar _gv_i_3;
	function uses_div;
		input reg [6:0] op;
		reg x;
		begin
			case (op)
				7'd32: x = 1'b1;
				7'd33: x = 1'b1;
				7'd34: x = 1'b1;
				7'd35: x = 1'b1;
				7'd85: x = 1'b1;
				7'd86: x = 1'b1;
				7'd87: x = 1'b1;
				7'd88: x = 1'b1;
				default: x = 1'b0;
			endcase
			uses_div = x;
		end
	endfunction
	function uses_mul;
		input reg [6:0] op;
		reg x;
		begin
			case (op)
				7'd29: x = 1'b1;
				7'd31: x = 1'b1;
				7'd30: x = 1'b1;
				7'd84: x = 1'b1;
				default: x = 1'b0;
			endcase
			uses_mul = x;
		end
	endfunction
	generate
		for (_gv_i_3 = 0; _gv_i_3 < N_INT_SCHED_ENTRIES; _gv_i_3 = _gv_i_3 + 1) begin : genblk3
			localparam i = _gv_i_3;
			always @(*) begin
				if (_sv2v_0)
					;
				t_alu_srcA_match[i] = r_alu_sched_uops[i][237] & (((((mem_rsp_dst_valid & (mem_rsp_dst_ptr == r_alu_sched_uops[i][244-:7])) | (t_mul_complete & (w_mul_prf_ptr == r_alu_sched_uops[i][244-:7]))) | (r_div_complete & (r_div_prf_ptr == r_alu_sched_uops[i][244-:7]))) | ((r_start_int2 & t_wr_int_prf2) & (int_uop2[228-:7] == r_alu_sched_uops[i][244-:7]))) | ((r_start_int & t_wr_int_prf) & (int_uop[228-:7] == r_alu_sched_uops[i][244-:7])));
				t_alu_srcB_match[i] = r_alu_sched_uops[i][229] & (((((mem_rsp_dst_valid & (mem_rsp_dst_ptr == r_alu_sched_uops[i][236-:7])) | (t_mul_complete & (w_mul_prf_ptr == r_alu_sched_uops[i][236-:7]))) | (r_div_complete & (r_div_prf_ptr == r_alu_sched_uops[i][236-:7]))) | ((r_start_int2 & t_wr_int_prf2) & (int_uop2[228-:7] == r_alu_sched_uops[i][236-:7]))) | ((r_start_int & t_wr_int_prf) & (int_uop[228-:7] == r_alu_sched_uops[i][236-:7])));
				t_alu_entry_rdy[i] = (r_alu_sched_valid[i] && (uses_div(r_alu_sched_uops[i][251-:7]) ? t_div_ready : (uses_mul(r_alu_sched_uops[i][251-:7]) ? !r_wb_bitvec[5] : !r_wb_bitvec[1])) ? (t_alu_srcA_match[i] | r_alu_srcA_rdy[i]) & (t_alu_srcB_match[i] | r_alu_srcB_rdy[i]) : 1'b0);
			end
			always @(posedge clk)
				if (reset) begin
					r_alu_srcA_rdy[i] <= 1'b0;
					r_alu_srcB_rdy[i] <= 1'b0;
				end
				else if (t_alu_alloc_entry[i]) begin
					r_alu_srcA_rdy[i] <= (uq[237] ? !r_prf_inflight[uq[244-:7]] | t_alu_alloc_srcA_match : 1'b1);
					r_alu_srcB_rdy[i] <= (uq[229] ? !r_prf_inflight[uq[236-:7]] | t_alu_alloc_srcB_match : 1'b1);
				end
				else if (t_alu_select_entry[i]) begin
					r_alu_srcA_rdy[i] <= 1'b0;
					r_alu_srcB_rdy[i] <= 1'b0;
				end
				else if (r_alu_sched_valid[i]) begin
					r_alu_srcA_rdy[i] <= r_alu_srcA_rdy[i] | t_alu_srcA_match[i];
					r_alu_srcB_rdy[i] <= r_alu_srcB_rdy[i] | t_alu_srcB_match[i];
				end
		end
	endgenerate
	genvar _gv_i_4;
	generate
		for (_gv_i_4 = 0; _gv_i_4 < N_INT_SCHED_ENTRIES; _gv_i_4 = _gv_i_4 + 1) begin : genblk4
			localparam i = _gv_i_4;
			always @(*) begin
				if (_sv2v_0)
					;
				t_alu_srcA_match2[i] = r_alu_sched_uops2[i][237] && (((((mem_rsp_dst_valid & (mem_rsp_dst_ptr == r_alu_sched_uops2[i][244-:7])) || (t_mul_complete && (w_mul_prf_ptr == r_alu_sched_uops2[i][244-:7]))) || (r_div_complete && (r_div_prf_ptr == r_alu_sched_uops2[i][244-:7]))) || (r_start_int2 && (t_wr_int_prf2 & (int_uop2[228-:7] == r_alu_sched_uops2[i][244-:7])))) || (r_start_int && (t_wr_int_prf & (int_uop[228-:7] == r_alu_sched_uops2[i][244-:7]))));
				t_alu_srcB_match2[i] = r_alu_sched_uops2[i][229] && (((((mem_rsp_dst_valid & (mem_rsp_dst_ptr == r_alu_sched_uops2[i][236-:7])) || (t_mul_complete && (w_mul_prf_ptr == r_alu_sched_uops2[i][236-:7]))) || (r_div_complete && (r_div_prf_ptr == r_alu_sched_uops2[i][236-:7]))) || (r_start_int2 && (t_wr_int_prf2 & (int_uop2[228-:7] == r_alu_sched_uops2[i][236-:7])))) || (r_start_int && (t_wr_int_prf & (int_uop[228-:7] == r_alu_sched_uops2[i][236-:7]))));
				t_alu_entry_rdy2[i] = (r_alu_sched_valid2[i] ? (t_alu_srcA_match2[i] | r_alu_srcA_rdy2[i]) & (t_alu_srcB_match2[i] | r_alu_srcB_rdy2[i]) : 1'b0);
			end
			always @(posedge clk)
				if (reset) begin
					r_alu_srcA_rdy2[i] <= 1'b0;
					r_alu_srcB_rdy2[i] <= 1'b0;
				end
				else if (t_alu_alloc_entry2[i]) begin
					r_alu_srcA_rdy2[i] <= (uq2[237] ? !r_prf_inflight[uq2[244-:7]] | t_alu_alloc_srcA_match2 : 1'b1);
					r_alu_srcB_rdy2[i] <= (uq2[229] ? !r_prf_inflight[uq2[236-:7]] | t_alu_alloc_srcB_match2 : 1'b1);
				end
				else if (t_alu_select_entry2[i]) begin
					r_alu_srcA_rdy2[i] <= 1'b0;
					r_alu_srcB_rdy2[i] <= 1'b0;
				end
				else if (r_alu_sched_valid2[i]) begin
					r_alu_srcA_rdy2[i] <= r_alu_srcA_rdy2[i] | t_alu_srcA_match2[i];
					r_alu_srcB_rdy2[i] <= r_alu_srcB_rdy2[i] | t_alu_srcB_match2[i];
				end
		end
	endgenerate
	reg t_left_shift2;
	reg t_signed_shift2;
	wire [63:0] w_shifter_out2;
	reg t_zero_shift_upper2;
	reg [5:0] t_shift_amt2;
	wire [63:0] w_pc2_4;
	shift_right #(.LG_W(6)) s1(
		.is_left(t_left_shift2),
		.is_signed(t_signed_shift2),
		.data((t_zero_shift_upper2 ? {{32 {(t_signed_shift2 ? t_srcA_2[31] : 1'b0)}}, t_srcA_2[31:0]} : t_srcA_2)),
		.distance(t_shift_amt2),
		.y(w_shifter_out2)
	);
	mwidth_add npc_2(
		.A(int_uop2[92-:64]),
		.B(64'd4),
		.Y(w_pc2_4)
	);
	reg t_sub2;
	reg t_addi_2;
	wire [31:0] w_s_sub32;
	wire [31:0] w_c_sub32;
	wire [31:0] w_add32;
	reg t_sub;
	reg t_addi;
	csa #(.N(32)) csa0(
		.a(t_srcA[31:0]),
		.b((t_addi ? int_uop[188:157] : (t_sub ? ~t_srcB[31:0] : t_srcB[31:0]))),
		.cin((t_sub ? 32'd1 : 32'd0)),
		.s(w_s_sub32),
		.cout(w_c_sub32)
	);
	wire [31:0] w_add32_srcA = {w_c_sub32[30:0], 1'b0};
	wire [31:0] w_add32_srcB = w_s_sub32;
	assign w_add32 = w_add32_srcA + w_add32_srcB;
	wire [63:0] w_as64_;
	wire [63:0] w_as64_2_;
	addsub #(.W(64)) as0(
		.A(t_srcA),
		.B((t_addi ? int_uop[220-:64] : t_srcB)),
		.is_sub(t_sub),
		.Y(w_as64_)
	);
	addsub #(.W(64)) as1(
		.A(t_srcA_2),
		.B((t_addi_2 ? int_uop2[220-:64] : t_srcB_2)),
		.is_sub(t_sub2),
		.Y(w_as64_2_)
	);
	wire [63:0] w_as64_sext = {{32 {w_as64_[31]}}, w_as64_[31:0]};
	wire [63:0] w_as64 = (mode64 ? w_as64_ : w_as64_sext);
	wire [63:0] w_as64_2_sext = {{32 {w_as64_2_[31]}}, w_as64_2_[31:0]};
	wire [63:0] w_as64_2 = (mode64 ? w_as64_2_ : w_as64_2_sext);
	wire [63:0] w_indirect_target2;
	mwidth_add itgt(
		.A(t_srcA_2),
		.B(int_uop2[220-:64]),
		.Y(w_indirect_target2)
	);
	wire [63:0] w_fe_indirect_target2 = {int_uop2[140-:48], int_uop2[156-:16]};
	wire w_mispredicted_indirect2 = w_indirect_target2 != w_fe_indirect_target2;
	always @(*) begin
		if (_sv2v_0)
			;
		t_sub2 = 1'b0;
		t_addi_2 = 1'b0;
		t_take_br2 = 1'b0;
		t_mispred_br2 = 1'b0;
		t_pc_2 = int_uop2[92-:64];
		t_left_shift2 = 1'b0;
		t_signed_shift2 = 1'b0;
		t_shift_amt2 = 'd0;
		t_alu_valid2 = 1'b0;
		t_result2 = 'd0;
		t_wr_int_prf2 = 1'b0;
		t_zero_shift_upper2 = 1'b0;
		case (int_uop2[251-:7])
			7'd46: begin
				t_take_br2 = t_srcA_2 != t_srcB_2;
				t_mispred_br2 = int_uop2[21] != t_take_br2;
				t_pc_2 = (t_take_br2 ? int_uop2[220-:64] : w_pc2_4);
				t_alu_valid2 = 1'b1;
			end
			7'd41: begin
				t_take_br2 = t_srcA_2 == t_srcB_2;
				t_mispred_br2 = int_uop2[21] != t_take_br2;
				t_pc_2 = (t_take_br2 ? int_uop2[220-:64] : w_pc2_4);
				t_alu_valid2 = 1'b1;
			end
			7'd44: begin
				t_take_br2 = $signed(t_srcA_2) < $signed(t_srcB_2);
				t_mispred_br2 = int_uop2[21] != t_take_br2;
				t_pc_2 = (t_take_br2 ? int_uop2[220-:64] : w_pc2_4);
				t_alu_valid2 = 1'b1;
			end
			7'd42: begin
				t_take_br2 = $signed(t_srcA_2) >= $signed(t_srcB_2);
				t_mispred_br2 = int_uop2[21] != t_take_br2;
				t_pc_2 = (t_take_br2 ? int_uop2[220-:64] : w_pc2_4);
				t_alu_valid2 = 1'b1;
			end
			7'd45: begin
				t_take_br2 = t_srcA_2 < t_srcB_2;
				t_mispred_br2 = int_uop2[21] != t_take_br2;
				t_pc_2 = (t_take_br2 ? int_uop2[220-:64] : w_pc2_4);
				t_alu_valid2 = 1'b1;
			end
			7'd43: begin
				t_take_br2 = t_srcA_2 >= t_srcB_2;
				t_mispred_br2 = int_uop2[21] != t_take_br2;
				t_pc_2 = (t_take_br2 ? int_uop2[220-:64] : w_pc2_4);
				t_alu_valid2 = 1'b1;
			end
			7'd65: begin
				t_take_br2 = 1'b1;
				t_mispred_br2 = int_uop2[21] != 1'b1;
				t_pc_2 = int_uop2[220-:64];
				t_result2 = w_pc2_4;
				t_alu_valid2 = 1'b1;
				t_wr_int_prf2 = 1'b1;
			end
			7'd68: begin
				t_take_br2 = 1'b1;
				t_mispred_br2 = w_mispredicted_indirect2;
				t_pc_2 = w_indirect_target2;
				t_alu_valid2 = 1'b1;
				t_result2 = w_pc2_4;
				t_wr_int_prf2 = 1'b1;
			end
			7'd66: begin
				t_take_br2 = 1'b1;
				t_mispred_br2 = w_mispredicted_indirect2;
				t_pc_2 = w_indirect_target2;
				t_alu_valid2 = 1'b1;
			end
			7'd67: begin
				t_take_br2 = 1'b1;
				t_mispred_br2 = w_mispredicted_indirect2;
				t_pc_2 = w_indirect_target2;
				t_alu_valid2 = 1'b1;
			end
			7'd70: begin
				t_addi_2 = 1'b1;
				t_result2 = w_as64_2;
				t_alu_valid2 = 1'b1;
				t_wr_int_prf2 = 1'b1;
			end
			7'd79: begin
				t_addi_2 = 1'b1;
				t_result2 = w_as64_2_sext;
				t_alu_valid2 = 1'b1;
				t_wr_int_prf2 = 1'b1;
			end
			7'd38: begin
				t_result2 = w_as64_2;
				t_alu_valid2 = 1'b1;
				t_wr_int_prf2 = 1'b1;
			end
			7'd77: begin
				t_result2 = w_as64_2_sext;
				t_alu_valid2 = 1'b1;
				t_wr_int_prf2 = 1'b1;
			end
			7'd4: begin
				t_result2 = {w_zf, $signed(t_srcA_2) < $signed(t_srcB_2)};
				t_alu_valid2 = 1'b1;
				t_wr_int_prf2 = 1'b1;
			end
			7'd5: begin
				t_result2 = {w_zf, t_srcA_2 < t_srcB_2};
				t_alu_valid2 = 1'b1;
				t_wr_int_prf2 = 1'b1;
			end
			7'd36: begin
				t_result2 = {w_zf, $signed(t_srcA_2) < $signed(int_uop2[220-:64])};
				t_alu_valid2 = 1'b1;
				t_wr_int_prf2 = 1'b1;
			end
			7'd37: begin
				t_result2 = {w_zf, t_srcA_2 < int_uop2[220-:64]};
				t_alu_valid2 = 1'b1;
				t_wr_int_prf2 = 1'b1;
			end
			7'd39: begin
				t_sub2 = 1'b1;
				t_result2 = w_as64_2;
				t_alu_valid2 = 1'b1;
				t_wr_int_prf2 = 1'b1;
			end
			7'd78: begin
				t_sub2 = 1'b1;
				t_result2 = w_as64_2_sext;
				t_alu_valid2 = 1'b1;
				t_wr_int_prf2 = 1'b1;
			end
			7'd40: begin
				t_result2 = int_uop2[220-:64] & t_srcA_2;
				t_alu_valid2 = 1'b1;
				t_wr_int_prf2 = 1'b1;
			end
			7'd62: begin
				t_result2 = int_uop2[220-:64] | t_srcA_2;
				t_alu_valid2 = 1'b1;
				t_wr_int_prf2 = 1'b1;
			end
			7'd63: begin
				t_result2 = int_uop2[220-:64] ^ t_srcA_2;
				t_alu_valid2 = 1'b1;
				t_wr_int_prf2 = 1'b1;
			end
			7'd74: begin
				t_result2 = t_srcA_2 & t_srcB_2;
				t_alu_valid2 = 1'b1;
				t_wr_int_prf2 = 1'b1;
			end
			7'd75: begin
				t_result2 = t_srcA_2 | t_srcB_2;
				t_alu_valid2 = 1'b1;
				t_wr_int_prf2 = 1'b1;
			end
			7'd76: begin
				t_result2 = t_srcA_2 ^ t_srcB_2;
				t_alu_valid2 = 1'b1;
				t_wr_int_prf2 = 1'b1;
			end
			7'd0: begin
				t_shift_amt2 = {(mode64 ? t_srcB_2[5] : 1'b0), t_srcB_2[4:0]};
				t_result2 = w_shifter_out2;
				t_wr_int_prf2 = 1'b1;
				t_alu_valid2 = 1'b1;
			end
			7'd50: begin
				t_shift_amt2 = {(mode64 ? int_uop2[162] : 1'b0), int_uop2[161:157]};
				t_result2 = w_shifter_out2;
				t_wr_int_prf2 = 1'b1;
				t_alu_valid2 = 1'b1;
			end
			7'd1: begin
				t_signed_shift2 = 1'b1;
				t_shift_amt2 = {(mode64 ? t_srcB_2[5] : 1'b0), t_srcB_2[4:0]};
				t_result2 = w_shifter_out2;
				t_wr_int_prf2 = 1'b1;
				t_alu_valid2 = 1'b1;
			end
			7'd83: begin
				t_signed_shift2 = 1'b1;
				t_shift_amt2 = {1'b0, t_srcB_2[4:0]};
				t_result2 = {{32 {w_shifter_out2[31]}}, w_shifter_out2[31:0]};
				t_wr_int_prf2 = 1'b1;
				t_alu_valid2 = 1'b1;
			end
			7'd90: begin
				t_zero_shift_upper2 = 1'b1;
				t_shift_amt2 = {1'b0, t_srcB_2[4:0]};
				t_result2 = {{32 {w_shifter_out2[31]}}, w_shifter_out2[31:0]};
				t_wr_int_prf2 = 1'b1;
				t_alu_valid2 = 1'b1;
			end
			7'd82: begin
				t_signed_shift2 = 1'b1;
				t_shift_amt2 = {1'b0, int_uop2[161:157]};
				t_result2 = {{32 {w_shifter_out2[31]}}, w_shifter_out2[31:0]};
				t_wr_int_prf2 = 1'b1;
				t_alu_valid2 = 1'b1;
				t_zero_shift_upper2 = 1'b1;
			end
			7'd81: begin
				t_shift_amt2 = {1'b0, int_uop2[161:157]};
				t_result2 = {{32 {w_shifter_out2[31]}}, w_shifter_out2[31:0]};
				t_wr_int_prf2 = 1'b1;
				t_alu_valid2 = 1'b1;
				t_zero_shift_upper2 = 1'b1;
			end
			7'd49: begin
				t_signed_shift2 = 1'b1;
				t_shift_amt2 = {(mode64 ? int_uop2[162] : 1'b0), int_uop2[161:157]};
				t_result2 = w_shifter_out2;
				t_wr_int_prf2 = 1'b1;
				t_alu_valid2 = 1'b1;
			end
			7'd47: begin
				t_left_shift2 = 1'b1;
				t_shift_amt2 = {(mode64 ? t_srcB_2[5] : 1'b0), t_srcB_2[4:0]};
				t_result2 = w_shifter_out2;
				t_wr_int_prf2 = 1'b1;
				t_alu_valid2 = 1'b1;
			end
			7'd89: begin
				t_left_shift2 = 1'b1;
				t_shift_amt2 = {1'b0, t_srcB_2[4:0]};
				t_result2 = {{32 {w_shifter_out2[31]}}, w_shifter_out2[31:0]};
				t_wr_int_prf2 = 1'b1;
				t_alu_valid2 = 1'b1;
			end
			7'd48: begin
				t_left_shift2 = 1'b1;
				t_shift_amt2 = {(mode64 ? int_uop2[162] : 1'b0), int_uop2[161:157]};
				t_result2 = w_shifter_out2;
				t_wr_int_prf2 = 1'b1;
				t_alu_valid2 = 1'b1;
			end
			7'd80: begin
				t_left_shift2 = 1'b1;
				t_shift_amt2 = int_uop2[162:157];
				t_result2 = {{32 {w_shifter_out2[31]}}, w_shifter_out2[31:0]};
				t_wr_int_prf2 = 1'b1;
				t_alu_valid2 = 1'b1;
			end
			7'd71: begin
				t_result2 = int_uop2[220-:64];
				t_alu_valid2 = 1'b1;
				t_wr_int_prf2 = 1'b1;
			end
			7'd72: begin
				t_result2 = int_uop2[220-:64];
				t_alu_valid2 = 1'b1;
				t_wr_int_prf2 = 1'b1;
			end
			default:
				;
		endcase
	end
	always @(posedge clk)
		if (reset || t_flash_clear)
			r_alu_sched_valid <= 'd0;
		else begin
			if (w_alloc_uq) begin
				r_alu_sched_valid[t_alu_sched_alloc_ptr[1:0]] <= 1'b1;
				r_alu_sched_uops[t_alu_sched_alloc_ptr[1:0]] <= uq;
			end
			if (t_alu_entry_rdy != 'd0)
				r_alu_sched_valid[t_alu_sched_select_ptr[1:0]] <= 1'b0;
		end
	always @(posedge clk)
		if (reset || t_flash_clear)
			r_alu_sched_valid2 <= 'd0;
		else begin
			if (w_alloc_uq2) begin
				r_alu_sched_valid2[t_alu_sched_alloc_ptr2[1:0]] <= 1'b1;
				r_alu_sched_uops2[t_alu_sched_alloc_ptr2[1:0]] <= uq2;
			end
			if (t_alu_entry_rdy2 != 'd0)
				r_alu_sched_valid2[t_alu_sched_select_ptr2[1:0]] <= 1'b0;
		end
	shift_right #(.LG_W(6)) s0(
		.is_left(t_left_shift),
		.is_signed(t_signed_shift),
		.data((t_zero_shift_upper ? {{32 {(t_signed_shift ? t_srcA[31] : 1'b0)}}, t_srcA[31:0]} : t_srcA)),
		.distance(t_shift_amt),
		.y(w_shifter_out)
	);
	always @(posedge clk) begin
		r_mul_prf_ptr <= w_mul_prf_ptr;
		r_div_prf_ptr <= w_div_prf_ptr;
		r_mul_complete <= (reset ? 1'b0 : t_mul_complete);
		r_div_complete <= (reset ? 1'b0 : t_div_complete);
	end
	mul m(
		.clk(clk),
		.reset(reset),
		.is_signed(t_signed_mul),
		.is_high((int_uop[251-:7] == 7'd31) || (int_uop[251-:7] == 7'd30)),
		.go(t_start_mul & r_start_int),
		.is_mulw(t_is_mulw),
		.src_A(t_srcA),
		.src_B(t_srcB),
		.rob_ptr_in(int_uop[28-:5]),
		.prf_ptr_in(int_uop[228-:7]),
		.y(t_mul_result),
		.complete(t_mul_complete),
		.rob_ptr_out(t_rob_ptr_out),
		.prf_ptr_val_out(),
		.prf_ptr_out(w_mul_prf_ptr)
	);
	always @(negedge clk) begin
		if (t_mul_complete & t_div_complete)
			$stop;
		if ((t_mul_complete & r_start_int) & t_wr_int_prf)
			$stop;
		if ((t_div_complete & r_start_int) & t_wr_int_prf) begin
			$display("divide completes but pc %x started at cycle %d", int_uop[92-:64], r_cycle);
			$stop;
		end
	end
	wire [63:0] w_divA = (t_zero_shift_upper ? {{32 {(t_signed_div ? t_srcA[31] : 1'b0)}}, t_srcA[31:0]} : t_srcA);
	wire [63:0] w_divB = (t_zero_shift_upper ? {{32 {(t_signed_div ? t_srcB[31] : 1'b0)}}, t_srcB[31:0]} : t_srcB);
	nu_divider #(.LG_W(6)) d64(
		.clk(clk),
		.reset(reset),
		.flush(ds_done),
		.wb_slot_used(r_start_int | t_mul_complete),
		.inA(w_divA),
		.inB(w_divB),
		.rob_ptr_in(int_uop[28-:5]),
		.prf_ptr_in(int_uop[228-:7]),
		.is_signed_div(t_signed_div),
		.is_w(t_zero_shift_upper),
		.is_rem(t_is_rem),
		.start_div(t_start_div64),
		.y(t_div_result),
		.rob_ptr_out(t_div_rob_ptr),
		.prf_ptr_out(w_div_prf_ptr),
		.complete(t_div_complete),
		.ready(t_div_ready)
	);
	assign divide_ready = t_div_ready;
	always @(*) begin
		if (_sv2v_0)
			;
		n_mq_head_ptr = r_mq_head_ptr;
		n_mq_tail_ptr = r_mq_tail_ptr;
		n_mq_next_tail_ptr = r_mq_next_tail_ptr;
		if (r_mem_ready) begin
			n_mq_tail_ptr = r_mq_tail_ptr + 'd1;
			n_mq_next_tail_ptr = r_mq_next_tail_ptr + 'd1;
		end
		if (mem_req_ack)
			n_mq_head_ptr = r_mq_head_ptr + 'd1;
		t_mem_head = r_mem_q[r_mq_head_ptr[1:0]];
		mem_q_empty = r_mq_head_ptr == r_mq_tail_ptr;
		mem_q_full = (r_mq_head_ptr != r_mq_tail_ptr) && (r_mq_head_ptr[1:0] == r_mq_tail_ptr[1:0]);
		mem_q_next_full = (r_mq_head_ptr != r_mq_next_tail_ptr) && (r_mq_head_ptr[1:0] == r_mq_next_tail_ptr[1:0]);
	end
	always @(posedge clk)
		if (r_mem_ready) begin
			r_mem_q[r_mq_tail_ptr[1:0]] <= t_mem_tail;
			if (mem_q_full)
				$stop;
		end
	always @(*) begin
		if (_sv2v_0)
			;
		n_mdq_head_ptr = r_mdq_head_ptr;
		n_mdq_tail_ptr = r_mdq_tail_ptr;
		n_mdq_next_tail_ptr = r_mdq_next_tail_ptr;
		if (r_dq_ready) begin
			n_mdq_tail_ptr = r_mdq_tail_ptr + 'd1;
			n_mdq_next_tail_ptr = r_mdq_next_tail_ptr + 'd1;
		end
		if (core_store_data_ack)
			n_mdq_head_ptr = r_mdq_head_ptr + 'd1;
		core_store_data = r_mdq[r_mdq_head_ptr[2:0]];
		mem_mdq_empty = r_mdq_head_ptr == r_mdq_tail_ptr;
		mem_mdq_full = (r_mdq_head_ptr != r_mdq_tail_ptr) && (r_mdq_head_ptr[2:0] == r_mdq_tail_ptr[2:0]);
		mem_mdq_next_full = (r_mdq_head_ptr != r_mdq_next_tail_ptr) && (r_mdq_head_ptr[2:0] == r_mdq_next_tail_ptr[2:0]);
	end
	assign mem_req = t_mem_head;
	assign mem_req_valid = !mem_q_empty;
	assign uq_wait = r_uq_wait;
	assign mq_wait = r_mq_wait;
	assign core_store_data_valid = !mem_mdq_empty;
	assign paging_active = r_paging_active;
	always @(posedge clk) begin
		r_mq_head_ptr <= (reset ? 'd0 : n_mq_head_ptr);
		r_mq_tail_ptr <= (reset ? 'd0 : n_mq_tail_ptr);
		r_mq_next_tail_ptr <= (reset ? 'd1 : n_mq_next_tail_ptr);
		r_mdq_head_ptr <= (reset | mem_dq_clr ? 'd0 : n_mdq_head_ptr);
		r_mdq_tail_ptr <= (reset | mem_dq_clr ? 'd0 : n_mdq_tail_ptr);
		r_mdq_next_tail_ptr <= (reset | mem_dq_clr ? 'd1 : n_mdq_next_tail_ptr);
	end
	always @(posedge clk)
		if (reset || ds_done)
			r_prf_inflight <= 'd0;
		else begin
			if (uq_push && uq_uop[221])
				r_prf_inflight[uq_uop[228-:7]] <= 1'b1;
			if (uq_push_two && uq_uop_two[221])
				r_prf_inflight[uq_uop_two[228-:7]] <= 1'b1;
			if (mem_rsp_dst_valid)
				r_prf_inflight[mem_rsp_dst_ptr] <= 1'b0;
			if (r_start_int && t_wr_int_prf)
				r_prf_inflight[int_uop[228-:7]] <= 1'b0;
			else if (t_mul_complete)
				r_prf_inflight[w_mul_prf_ptr] <= 1'b0;
			else if (t_div_complete)
				r_prf_inflight[w_div_prf_ptr] <= 1'b0;
			if (r_start_int2 && t_wr_int_prf2)
				r_prf_inflight[int_uop2[228-:7]] <= 1'b0;
		end
	wire [63:0] w_pc4;
	wire [63:0] w_indirect_target;
	mwidth_add add2(
		.A(t_srcA),
		.B(int_uop[220-:64]),
		.Y(w_indirect_target)
	);
	wire [63:0] w_fe_indirect_target = {int_uop[140-:48], int_uop[156-:16]};
	wire w_mispredicted_indirect = w_indirect_target != w_fe_indirect_target;
	mwidth_add add3(
		.A(int_uop[92-:64]),
		.B(64'd4),
		.Y(w_pc4)
	);
	wire w_srcB_is_zero = t_srcB == 64'd0;
	always @(*) begin
		if (_sv2v_0)
			;
		t_sub = 1'b0;
		t_addi = 1'b0;
		t_pc = int_uop[92-:64];
		t_result = 'd0;
		t_has_cause = 1'b0;
		t_cause = 5'd0;
		t_clear_tlb = 1'b0;
		t_wr_csr_en = 1'b0;
		t_rd_csr_en = 1'b0;
		t_wr_priv = 1'b0;
		t_priv = 2'd0;
		t_wr_csr = 64'd0;
		t_wr_int_prf = 1'b0;
		t_take_br = 1'b0;
		t_mispred_br = 1'b0;
		t_alu_valid = 1'b0;
		t_got_break = 1'b0;
		t_signed_shift = 1'b0;
		t_left_shift = 1'b0;
		t_shift_amt = 'd0;
		t_start_mul = 1'b0;
		t_signed_mul = 1'b0;
		t_is_mulw = 1'b0;
		t_signed_div = 1'b0;
		t_is_rem = 1'b0;
		t_start_div32 = 1'b0;
		t_start_div64 = 1'b0;
		t_zero_shift_upper = 1'b0;
		case (int_uop[251-:7])
			7'd32: begin
				t_signed_div = 1'b1;
				t_start_div64 = r_start_int & !ds_done;
			end
			7'd85: begin
				t_signed_div = 1'b1;
				t_zero_shift_upper = 1'b1;
				t_start_div64 = r_start_int & !ds_done;
			end
			7'd33: t_start_div64 = r_start_int & !ds_done;
			7'd86: begin
				t_zero_shift_upper = 1'b1;
				t_start_div64 = r_start_int & !ds_done;
			end
			7'd34: begin
				t_signed_div = 1'b1;
				t_is_rem = 1'b1;
				t_start_div64 = r_start_int & !ds_done;
			end
			7'd35: begin
				t_is_rem = 1'b1;
				t_start_div64 = r_start_int & !ds_done;
			end
			7'd87: begin
				t_zero_shift_upper = 1'b1;
				t_signed_div = 1'b1;
				t_is_rem = 1'b1;
				t_start_div64 = r_start_int & !ds_done;
			end
			7'd88: begin
				t_zero_shift_upper = 1'b1;
				t_is_rem = 1'b1;
				t_start_div64 = r_start_int & !ds_done;
			end
			7'd29: begin
				t_signed_mul = 1'b1;
				t_start_mul = r_start_int & !ds_done;
			end
			7'd84: begin
				t_is_mulw = 1'b1;
				t_signed_mul = 1'b1;
				t_start_mul = r_start_int & !ds_done;
			end
			7'd30: begin
				t_signed_mul = 1'b1;
				t_start_mul = r_start_int & !ds_done;
			end
			7'd31: t_start_mul = r_start_int & !ds_done;
			7'd70: begin
				t_addi = 1'b1;
				t_result = w_as64;
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd79: begin
				t_addi = 1'b1;
				t_result = w_as64_sext;
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd38: begin
				t_result = w_as64;
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd77: begin
				t_result = w_as64_sext;
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd78: begin
				t_sub = 1'b1;
				t_result = w_as64_sext;
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd14: begin
				t_result = r_cycle[63:0];
				t_alu_valid = 1'b1;
				t_wr_int_prf = 1'b1;
				t_pc = w_pc4;
			end
			7'd15: begin
				t_result = r_retired_insns[63:0];
				t_alu_valid = 1'b1;
				t_wr_int_prf = 1'b1;
				t_pc = w_pc4;
			end
			7'd16: begin
				t_result = r_branches[63:0];
				t_alu_valid = 1'b1;
				t_wr_int_prf = 1'b1;
				t_pc = w_pc4;
			end
			7'd17: begin
				t_result = r_branch_faults[63:0];
				t_alu_valid = 1'b1;
				t_wr_int_prf = 1'b1;
				t_pc = w_pc4;
			end
			7'd74: begin
				t_result = t_srcA & t_srcB;
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd39: begin
				t_sub = 1'b1;
				t_result = w_as64;
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd40: begin
				t_result = t_srcA & int_uop[220-:64];
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd71: begin
				t_result = int_uop[220-:64];
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd41: begin
				t_take_br = t_srcA == t_srcB;
				t_mispred_br = int_uop[21] != t_take_br;
				t_pc = (t_take_br ? int_uop[220-:64] : w_pc4);
				t_alu_valid = 1'b1;
			end
			7'd91: begin
				t_result = (w_srcB_is_zero ? 64'd0 : t_srcA);
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd92: begin
				t_result = (!w_srcB_is_zero ? 64'd0 : t_srcA);
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd42: begin
				t_take_br = $signed(t_srcA) >= $signed(t_srcB);
				t_mispred_br = int_uop[21] != t_take_br;
				t_pc = (t_take_br ? int_uop[220-:64] : w_pc4);
				t_alu_valid = 1'b1;
			end
			7'd43: begin
				t_take_br = t_srcA >= t_srcB;
				t_mispred_br = int_uop[21] != t_take_br;
				t_pc = (t_take_br ? int_uop[220-:64] : w_pc4);
				t_alu_valid = 1'b1;
			end
			7'd44: begin
				t_take_br = $signed(t_srcA) < $signed(t_srcB);
				t_mispred_br = int_uop[21] != t_take_br;
				t_pc = (t_take_br ? int_uop[220-:64] : w_pc4);
				t_alu_valid = 1'b1;
			end
			7'd45: begin
				t_take_br = t_srcA < t_srcB;
				t_mispred_br = int_uop[21] != t_take_br;
				t_pc = (t_take_br ? int_uop[220-:64] : w_pc4);
				t_alu_valid = 1'b1;
			end
			7'd46: begin
				t_take_br = t_srcA != t_srcB;
				t_mispred_br = int_uop[21] != t_take_br;
				t_pc = (t_take_br ? int_uop[220-:64] : w_pc4);
				t_alu_valid = 1'b1;
			end
			7'd65: begin
				t_take_br = 1'b1;
				t_mispred_br = int_uop[21] != t_take_br;
				t_pc = int_uop[220-:64];
				t_result = w_pc4;
				t_alu_valid = 1'b1;
				t_wr_int_prf = 1'b1;
			end
			7'd68: begin
				t_take_br = 1'b1;
				t_mispred_br = w_mispredicted_indirect;
				t_pc = w_indirect_target;
				t_alu_valid = 1'b1;
				t_result = w_pc4;
				t_wr_int_prf = 1'b1;
			end
			7'd66: begin
				t_take_br = 1'b1;
				t_mispred_br = w_mispredicted_indirect;
				t_pc = w_indirect_target;
				t_alu_valid = 1'b1;
			end
			7'd67: begin
				t_take_br = 1'b1;
				t_mispred_br = w_mispredicted_indirect;
				t_pc = w_indirect_target;
				t_alu_valid = 1'b1;
			end
			7'd72: begin
				t_result = int_uop[220-:64];
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd75: begin
				t_result = t_srcA | t_srcB;
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd62: begin
				t_result = t_srcA | int_uop[220-:64];
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd47: begin
				t_left_shift = 1'b1;
				t_shift_amt = {(mode64 ? t_srcB[5] : 1'b0), t_srcB[4:0]};
				t_result = w_shifter_out;
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd89: begin
				t_left_shift = 1'b1;
				t_shift_amt = {1'b0, t_srcB[4:0]};
				t_result = {{32 {w_shifter_out[31]}}, w_shifter_out[31:0]};
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd48: begin
				t_left_shift = 1'b1;
				t_shift_amt = {(mode64 ? int_uop[162] : 1'b0), int_uop[161:157]};
				t_result = w_shifter_out;
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd80: begin
				t_left_shift = 1'b1;
				t_shift_amt = {1'b0, int_uop[161:157]};
				t_result = {{32 {w_shifter_out[31]}}, w_shifter_out[31:0]};
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd4: begin
				t_result = {w_zf, $signed(t_srcA) < $signed(t_srcB)};
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd5: begin
				t_result = {w_zf, t_srcA < t_srcB};
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd36: begin
				t_result = {w_zf, $signed(t_srcA) < $signed(int_uop[220-:64])};
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd37: begin
				t_result = {w_zf, t_srcA < int_uop[220-:64]};
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd82: begin
				t_zero_shift_upper = 1'b1;
				t_signed_shift = 1'b1;
				t_shift_amt = {1'b0, int_uop[161:157]};
				t_result = {{32 {w_shifter_out[31]}}, w_shifter_out[31:0]};
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd81: begin
				t_zero_shift_upper = 1'b1;
				t_shift_amt = {1'b0, int_uop[161:157]};
				t_result = {{32 {w_shifter_out[31]}}, w_shifter_out[31:0]};
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd49: begin
				t_signed_shift = 1'b1;
				t_shift_amt = {(mode64 ? int_uop[162] : 1'b0), int_uop[161:157]};
				t_result = w_shifter_out;
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd83: begin
				t_signed_shift = 1'b1;
				t_shift_amt = {1'b0, t_srcB[4:0]};
				t_result = {{32 {w_shifter_out[31]}}, w_shifter_out[31:0]};
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd90: begin
				t_zero_shift_upper = 1'b1;
				t_shift_amt = {1'b0, t_srcB[4:0]};
				t_result = {{32 {w_shifter_out[31]}}, w_shifter_out[31:0]};
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd1: begin
				t_signed_shift = 1'b1;
				t_shift_amt = {(mode64 ? t_srcB[5] : 1'b0), t_srcB[4:0]};
				t_result = w_shifter_out;
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd0: begin
				t_shift_amt = {(mode64 ? t_srcB[5] : 1'b0), t_srcB[4:0]};
				t_result = w_shifter_out;
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd50: begin
				t_shift_amt = {(mode64 ? int_uop[162] : 1'b0), int_uop[161:157]};
				t_result = w_shifter_out;
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd63: begin
				t_result = t_srcA ^ int_uop[220-:64];
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd76: begin
				t_result = t_srcA ^ t_srcB;
				t_wr_int_prf = 1'b1;
				t_alu_valid = 1'b1;
			end
			7'd21: begin
				t_rd_csr_en = 1'b1;
				t_wr_csr_en = r_start_int;
				t_wr_csr = t_rd_csr;
				t_wr_priv = r_start_int;
				t_priv = {1'b0, r_mstatus[8]};
				t_pc = r_sepc;
				t_alu_valid = 1'b1;
			end
			7'd20: begin
				t_rd_csr_en = 1'b1;
				t_wr_csr_en = r_start_int;
				t_wr_csr = t_rd_csr;
				t_wr_priv = r_start_int;
				t_priv = w_mpp;
				t_pc = r_mepc;
				t_alu_valid = 1'b1;
			end
			7'd18: begin
				t_has_cause = 1'b1;
				t_cause = (r_priv == 'd0 ? 5'd8 : (r_priv == 'd1 ? 5'd9 : (r_priv == 'd2 ? 5'd10 : 5'd11)));
				t_alu_valid = 1'b1;
			end
			7'd19: begin
				t_has_cause = 1'b1;
				t_cause = 5'd3;
				t_alu_valid = 1'b1;
			end
			7'd28: begin
				t_pc = w_pc4;
				t_alu_valid = 1'b1;
				t_clear_tlb = r_start_int;
			end
			7'd93: begin
				t_pc = w_pc4;
				t_alu_valid = 1'b1;
			end
			7'd22: begin
				t_rd_csr_en = 1'b1;
				t_result = t_rd_csr;
				t_wr_csr_en = r_start_int;
				t_wr_csr = t_srcA;
				t_wr_int_prf = int_uop[221];
				t_alu_valid = 1'b1;
				t_pc = w_pc4;
			end
			7'd23: begin
				t_rd_csr_en = 1'b1;
				t_result = t_rd_csr;
				t_wr_csr_en = r_start_int & (int_uop[151:147] != 'd0);
				t_wr_csr = t_rd_csr | t_srcA;
				t_wr_int_prf = int_uop[221];
				t_alu_valid = 1'b1;
				t_pc = w_pc4;
			end
			7'd24: begin
				t_rd_csr_en = 1'b1;
				t_result = t_rd_csr;
				t_wr_csr_en = r_start_int & (int_uop[151:147] != 'd0);
				t_wr_csr = t_rd_csr & ~t_srcA;
				t_wr_int_prf = int_uop[221];
				t_alu_valid = 1'b1;
				t_pc = w_pc4;
			end
			7'd25: begin
				t_rd_csr_en = 1'b1;
				t_wr_csr_en = r_start_int;
				t_wr_csr = {59'd0, int_uop[151:147]};
				t_result = t_rd_csr;
				t_wr_int_prf = int_uop[221];
				t_alu_valid = 1'b1;
				t_pc = w_pc4;
			end
			7'd26: begin
				t_rd_csr_en = 1'b1;
				t_wr_csr_en = (int_uop[151:147] != 'd0) & r_start_int;
				t_wr_csr = t_rd_csr | {59'd0, int_uop[151:147]};
				t_result = t_rd_csr;
				t_wr_int_prf = int_uop[221];
				t_alu_valid = 1'b1;
				t_pc = w_pc4;
			end
			7'd27: begin
				t_rd_csr_en = 1'b1;
				t_wr_csr_en = (int_uop[151:147] != 'd0) & r_start_int;
				t_wr_csr = t_rd_csr & ~{59'd0, int_uop[151:147]};
				t_result = t_rd_csr;
				t_wr_int_prf = int_uop[221];
				t_alu_valid = 1'b1;
				t_pc = w_pc4;
			end
			7'd69: t_cause = 5'd3;
			7'd96: begin
				t_has_cause = 1'b1;
				t_cause = 5'd2;
				t_alu_valid = 1'b1;
			end
			7'd94: begin
				t_has_cause = 1'b1;
				t_cause = 5'd12;
				t_alu_valid = 1'b1;
			end
			default: begin
				t_has_cause = 1'b1;
				t_cause = 5'd2;
				t_alu_valid = 1'b1;
			end
		endcase
	end
	reg t_delegate;
	assign page_table_root = {8'd0, r_satp[43:0], 12'd0};
	wire [31:0] w_mideleg = r_mideleg[31:0];
	wire [15:0] w_medeleg = r_medeleg[15:0];
	always @(*) begin
		if (_sv2v_0)
			;
		t_delegate = 1'b0;
		if (r_priv[1] == 1'b0)
			t_delegate = (irq ? w_mideleg[cause] : w_medeleg[cause[3:0]]);
		exc_pc = (t_delegate ? r_stvec : r_mtvec);
	end
	always @(posedge clk) r_clear_tlb <= (reset ? 1'b0 : t_clear_tlb);
	reg r_priv_update0;
	reg r_priv_update;
	assign priv_update = r_priv_update;
	always @(posedge clk)
		if (reset) begin
			r_priv_update0 <= 1'b0;
			r_priv_update <= 1'b0;
		end
		else begin
			r_priv_update0 <= update_csr_exc | t_wr_priv;
			r_priv_update <= r_priv_update0;
		end
	always @(*) begin
		if (_sv2v_0)
			;
		n_priv = r_priv;
		if (update_csr_exc)
			n_priv = (t_delegate ? 'd1 : 'd3);
		else if (t_wr_priv)
			n_priv = t_priv;
	end
	always @(posedge clk)
		if (reset)
			r_priv <= 2'd3;
		else
			r_priv <= n_priv;
	reg [3:0] r_rd_pc_idx;
	reg [3:0] n_rd_pc_idx;
	reg [3:0] r_wr_pc_idx;
	reg [3:0] n_wr_pc_idx;
	reg [7:0] r_pc_buf [7:0];
	always @(*) begin
		if (_sv2v_0)
			;
		n_wr_pc_idx = r_wr_pc_idx;
		n_rd_pc_idx = r_rd_pc_idx;
		t_push_putchar = t_wr_csr_en & (6'd29 == int_uop[146:141]);
		if (t_push_putchar)
			n_wr_pc_idx = r_wr_pc_idx + 'd1;
		if (putchar_fifo_pop)
			n_rd_pc_idx = r_rd_pc_idx + 'd1;
	end
	always @(posedge clk) begin
		r_wr_pc_idx <= (reset ? 'd0 : n_wr_pc_idx);
		r_rd_pc_idx <= (reset ? 'd0 : n_rd_pc_idx);
	end
	always @(posedge clk)
		if (t_push_putchar)
			r_pc_buf[r_wr_pc_idx[2:0]] <= t_wr_csr[7:0];
	assign putchar_fifo_out = r_pc_buf[r_rd_pc_idx[2:0]];
	assign putchar_fifo_empty = r_wr_pc_idx == r_rd_pc_idx;
	wire w_putchar_fifo_full = (r_wr_pc_idx[2:0] == r_rd_pc_idx[2:0]) & (r_wr_pc_idx[3] != r_rd_pc_idx[3]);
	assign putchar_fifo_wptr = r_wr_pc_idx;
	assign putchar_fifo_rptr = r_rd_pc_idx;
	always @(*) begin
		if (_sv2v_0)
			;
		t_rd_csr = 'd0;
		case (int_uop[146:141])
			6'd0: t_rd_csr = r_mstatus & 64'h00000003000de133;
			6'd1: t_rd_csr = r_mie & r_mideleg;
			6'd2: t_rd_csr = r_stvec;
			6'd3: t_rd_csr = r_sscratch;
			6'd4: t_rd_csr = r_sepc;
			6'd5: t_rd_csr = r_scause;
			6'd6: t_rd_csr = r_scounteren;
			6'd7: t_rd_csr = r_stval;
			6'd8: t_rd_csr = r_mip & r_mideleg;
			6'd9: t_rd_csr = r_satp;
			6'd10: t_rd_csr = r_mstatus;
			6'd12: t_rd_csr = r_mcause;
			6'd13: t_rd_csr = r_mcounteren;
			6'd14: t_rd_csr = r_misa;
			6'd17: t_rd_csr = r_mtvec;
			6'd11: t_rd_csr = r_mie;
			6'd16: t_rd_csr = r_mideleg;
			6'd15: t_rd_csr = r_medeleg;
			6'd18: t_rd_csr = r_mepc;
			6'd20: t_rd_csr = r_mscratch;
			6'd19: t_rd_csr = r_mip;
			6'd21: t_rd_csr = r_pmpaddr0;
			6'd22: t_rd_csr = r_pmpaddr1;
			6'd23: t_rd_csr = r_pmpaddr2;
			6'd24: t_rd_csr = r_pmpaddr3;
			6'd25: t_rd_csr = r_pmpcfg0;
			6'd29: t_rd_csr = {63'd0, w_putchar_fifo_full};
			6'd30: t_rd_csr = 'd0;
			6'd27: t_rd_csr = r_mtime;
			6'd31: t_rd_csr = counters[511-:64];
			6'd32: t_rd_csr = counters[447-:64];
			6'd33: t_rd_csr = counters[639-:64];
			6'd34: t_rd_csr = counters[575-:64];
			6'd35: t_rd_csr = counters[383-:64];
			6'd36: t_rd_csr = counters[319-:64];
			6'd37: t_rd_csr = counters[255-:64];
			6'd38: t_rd_csr = counters[191-:64];
			6'd39: t_rd_csr = counters[127-:64];
			6'd40: t_rd_csr = counters[63-:64];
			default:
				if (t_rd_csr_en) begin
					$display("read csr %d unimplemented for pc %x", int_uop[146:141], int_uop[92-:64]);
					$stop;
				end
		endcase
	end
	reg r_satp_armed;
	reg n_paging_active;
	always @(*) begin
		if (_sv2v_0)
			;
		n_paging_active = r_satp_armed & !r_priv[1];
	end
	always @(posedge clk)
		if (reset)
			r_paging_active <= 1'b0;
		else
			r_paging_active <= n_paging_active;
	wire [3:0] w_mret_mstatus_b30 = (w_mpp == 2'd0 ? {r_mstatus[3:1], w_mpie} : (w_mpp == 2'd1 ? {r_mstatus[3:2], w_mpie, r_mstatus[0]} : (w_mpp == 2'd2 ? {r_mstatus[3], w_mpie, r_mstatus[1:0]} : {w_mpie, r_mstatus[2:0]})));
	wire [1:0] w_sret_mstatus_b10 = (w_spp ? {w_spie, r_mstatus[0]} : {r_mstatus[1], w_spie});
	wire [63:0] w_mret_mstatus = {r_mstatus[63:13], 2'd0, r_mstatus[10:8], 1'b1, r_mstatus[6:4], w_mret_mstatus_b30};
	wire [63:0] w_sret_mstatus = {r_mstatus[63:9], 1'd0, r_mstatus[7:6], 1'b1, r_mstatus[4:2], w_sret_mstatus_b10};
	wire w_ie = (r_priv == 2'd0 ? r_mstatus[0] : (r_priv == 2'd1 ? r_mstatus[1] : (r_priv == 2'd2 ? r_mstatus[2] : r_mstatus[3])));
	wire [63:0] w_exc_del_mstatus = {r_mstatus[63:9], r_priv[0], r_mstatus[7:6], w_ie, r_mstatus[4:2], 1'b0, r_mstatus[0]};
	wire [63:0] w_exc_mstatus = {r_mstatus[63:13], r_priv, r_mstatus[10:8], w_ie, r_mstatus[6:4], 1'b0, r_mstatus[2:0]};
	reg [63:0] r_foo;
	always @(posedge clk) r_foo <= (reset ? 'd0 : r_mstatus);
	always @(posedge clk)
		if (reset)
			r_mtime <= 'd0;
		else
			r_mtime <= r_mtime + 'd1;
	always @(posedge clk)
		if (reset) begin
			r_scounteren <= 'd0;
			r_satp <= 'd0;
			r_mie <= 'd0;
			r_mip <= 'd0;
			r_mstatus <= 64'h0000000a00000000;
			r_mcounteren <= 'd0;
			r_satp_armed <= 1'b0;
			r_pmpaddr0 <= 'd0;
			r_pmpaddr1 <= 'd0;
			r_pmpaddr2 <= 'd0;
			r_pmpaddr3 <= 'd0;
			r_pmpcfg0 <= 'd0;
			r_misa <= 64'h8000000000141101;
		end
		else if (update_csr_exc) begin
			if (t_delegate) begin
				r_scause <= {irq, 58'd0, cause};
				r_stval <= tval;
				r_sepc <= epc;
				r_mstatus <= w_exc_del_mstatus;
			end
			else begin
				r_mcause <= {irq, 58'd0, cause};
				r_mtval <= tval;
				r_mepc <= epc;
				r_mstatus <= w_exc_mstatus;
			end
		end
		else if (t_wr_csr_en)
			case (int_uop[146:141])
				6'd0: r_mstatus <= (t_wr_csr & 64'h00000000000de133) | (r_mstatus & ~64'h00000000000de133);
				6'd1: r_mie <= (r_mie & ~r_mideleg) | (t_wr_csr & r_mideleg);
				6'd2: r_stvec <= t_wr_csr;
				6'd3: r_sscratch <= t_wr_csr;
				6'd4: r_sepc <= t_wr_csr;
				6'd6: r_scounteren <= t_wr_csr;
				6'd5: r_scause <= t_wr_csr;
				6'd7: r_stval <= t_wr_csr;
				6'd8: r_mip <= (r_mip & ~r_mideleg) | (t_wr_csr & r_mideleg);
				6'd9:
					if ((t_wr_csr[63:60] == 4'h8) && (t_wr_csr[59:44] == 'd0)) begin
						r_satp_armed <= 1'b1;
						r_satp <= t_wr_csr;
					end
					else if (t_wr_csr[63:60] == 4'h0) begin
						r_satp_armed <= 1'b0;
						r_satp <= t_wr_csr;
					end
				6'd10:
					if (int_uop[251-:7] == 7'd20)
						r_mstatus <= w_mret_mstatus;
					else if (int_uop[251-:7] == 7'd21)
						r_mstatus <= w_sret_mstatus;
					else
						r_mstatus <= (t_wr_csr & 64'h00000000000e79bb) | (r_mstatus & 64'hfffffffffff18644);
				6'd13: r_mcounteren <= t_wr_csr;
				6'd14: r_misa <= t_wr_csr;
				6'd17: r_mtvec <= t_wr_csr;
				6'd11: r_mie <= t_wr_csr;
				6'd19: r_mip <= t_wr_csr;
				6'd12: r_mcause <= t_wr_csr;
				6'd15: r_medeleg <= t_wr_csr;
				6'd16: r_mideleg <= t_wr_csr;
				6'd20: r_mscratch <= t_wr_csr;
				6'd18: r_mepc <= t_wr_csr;
				6'd21: r_pmpaddr0 <= t_wr_csr;
				6'd22: r_pmpaddr1 <= t_wr_csr;
				6'd23: r_pmpaddr2 <= t_wr_csr;
				6'd24: r_pmpaddr3 <= t_wr_csr;
				6'd25: r_pmpcfg0 <= t_wr_csr;
				6'd29:
					;
				default: begin
					$display("write csr implement %d for pc %x opcode %d", int_uop[146:141], int_uop[92-:64], int_uop[251-:7]);
					$stop;
				end
			endcase
		else if (mtimecmp_val)
			r_mip <= {r_mip[63:8], 1'b0, r_mip[6:0]};
		else if (w_mtip)
			r_mip <= {r_mip[63:8], 1'b1, r_mip[6:0]};
	wire w_dq_ready = ((!r_prf_inflight[t_mem_dq[6-:7]] | t_fwd_int_mem_srcB) | t_fwd_mem_mem_srcB) | t_fwd_int2_mem_srcB;
	always @(*) begin
		if (_sv2v_0)
			;
		t_pop_mem_dq = (((t_mem_dq_empty == 1'b0) & (mem_dq_clr == 1'b0)) & w_dq_ready) & ((mem_mdq_next_full | mem_mdq_full) == 1'b0);
	end
	always @(*) begin
		if (_sv2v_0)
			;
		t_core_store_data[4-:5] = mem_dq[11-:5];
		t_core_store_data[68-:64] = t_mem_srcB;
		core_store_data_ptr = mem_dq[11-:5];
		core_store_data_ptr_valid = r_dq_ready;
	end
	always @(posedge clk)
		if (r_dq_ready)
			r_mdq[r_mdq_tail_ptr[2:0]] <= t_core_store_data;
	always @(posedge clk) r_dq_ready <= (reset ? 1'b0 : t_pop_mem_dq);
	always @(*) begin
		if (_sv2v_0)
			;
		t_picked_mem_uop = r_mem_sched_uops[t_mem_sched_select_ptr[1:0]];
	end
	reg [3:0] r_restart_counter;
	always @(posedge clk) r_restart_counter <= (reset ? 'd0 : (restart_complete ? r_restart_counter + 'd1 : r_restart_counter));
	find_first_set #(2) ffs_mem_sched_alloc(
		.in(~r_mem_sched_valid),
		.y(t_mem_sched_alloc_ptr)
	);
	wire w_mem_sched_avail = (&r_mem_sched_valid == 1'b0) & !t_flash_clear;
	always @(*) begin
		if (_sv2v_0)
			;
		t_pop_mem_uq = !t_mem_uq_empty & w_mem_sched_avail;
	end
	always @(*) begin
		if (_sv2v_0)
			;
		t_mem_alloc_srcA_match = (((mem_rsp_dst_valid & (mem_rsp_dst_ptr == t_mem_uq[244-:7])) | (t_mul_complete & (w_mul_prf_ptr == t_mem_uq[244-:7]))) | ((r_start_int2 & t_wr_int_prf2) & (int_uop2[228-:7] == t_mem_uq[244-:7]))) | ((r_start_int & t_wr_int_prf) & (int_uop[228-:7] == t_mem_uq[244-:7]));
	end
	genvar _gv_i_5;
	generate
		for (_gv_i_5 = 0; _gv_i_5 < N_MEM_SCHED_ENTRIES; _gv_i_5 = _gv_i_5 + 1) begin : genblk5
			localparam i = _gv_i_5;
			always @(*) begin
				if (_sv2v_0)
					;
				t_mem_srcA_match[i] = ((((mem_rsp_dst_valid & (mem_rsp_dst_ptr == r_mem_sched_uops[i][244-:7])) | (t_mul_complete & (w_mul_prf_ptr == r_mem_sched_uops[i][244-:7]))) | (r_div_complete & (r_div_prf_ptr == r_mem_sched_uops[i][244-:7]))) | ((r_start_int2 & t_wr_int_prf2) & (int_uop2[228-:7] == r_mem_sched_uops[i][244-:7]))) | ((r_start_int & t_wr_int_prf) & (int_uop[228-:7] == r_mem_sched_uops[i][244-:7]));
				t_mem_entry_reg_rdy[i] = (r_mem_sched_valid[i] & !(mem_q_next_full | mem_q_full) ? t_mem_srcA_match[i] | r_mem_srcA_rdy[i] : 1'b0);
			end
			always @(posedge clk)
				if (reset)
					r_mem_srcA_rdy[i] <= 1'b0;
				else if (t_mem_alloc_entry[i])
					r_mem_srcA_rdy[i] <= !r_prf_inflight[t_mem_uq[244-:7]] | t_mem_alloc_srcA_match;
				else if (t_mem_select_entry[i])
					r_mem_srcA_rdy[i] <= 1'b0;
				else if (r_mem_sched_valid[i])
					r_mem_srcA_rdy[i] <= r_mem_srcA_rdy[i] | t_mem_srcA_match[i];
		end
	endgenerate
	always @(*) begin
		if (_sv2v_0)
			;
		t_mem_alloc_entry = 'd0;
		t_mem_select_entry = 'd0;
		if (t_pop_mem_uq)
			t_mem_alloc_entry[t_mem_sched_alloc_ptr[1:0]] = 1'b1;
		if (|w_mem_sched_oldest_ready)
			t_mem_select_entry[t_mem_sched_select_ptr[1:0]] = 1'b1;
	end
	reg t_is_load;
	always @(*) begin
		if (_sv2v_0)
			;
		t_is_load = ((((((t_mem_uq[251-:7] == 7'd53) | (t_mem_uq[251-:7] == 7'd54)) | (t_mem_uq[251-:7] == 7'd55)) | (t_mem_uq[251-:7] == 7'd51)) | (t_mem_uq[251-:7] == 7'd56)) | (t_mem_uq[251-:7] == 7'd57)) | (t_mem_uq[251-:7] == 7'd52);
	end
	always @(posedge clk)
		if (reset | t_flash_clear) begin
			r_mem_sched_valid <= 'd0;
			r_mem_sched_store <= 'd0;
		end
		else begin
			if (t_pop_mem_uq) begin
				r_mem_sched_valid[t_mem_sched_alloc_ptr[1:0]] <= 1'b1;
				r_mem_sched_store[t_mem_sched_alloc_ptr[1:0]] <= t_is_load == 1'b0;
				r_mem_sched_uops[t_mem_sched_alloc_ptr[1:0]] <= t_mem_uq;
			end
			if (|w_mem_sched_oldest_ready) begin
				r_mem_sched_valid[t_mem_sched_select_ptr[1:0]] <= 1'b0;
				r_mem_sched_store[t_mem_sched_select_ptr[1:0]] <= 1'b0;
			end
		end
	always @(*) begin
		if (_sv2v_0)
			;
		t_mem_sched_mask_valid = r_mem_sched_valid & ~t_mem_select_entry;
	end
	genvar _gv_i_6;
	generate
		for (_gv_i_6 = 0; _gv_i_6 < N_MEM_SCHED_ENTRIES; _gv_i_6 = _gv_i_6 + 1) begin : genblk6
			localparam i = _gv_i_6;
			assign w_mem_sched_oldest_ready[i] = (|r_mem_sched_store ? t_mem_entry_reg_rdy[i] & (|r_mem_sched_matrix[i] == 1'b0) : t_mem_entry_reg_rdy[i] & ~(|(t_mem_entry_reg_rdy & r_mem_sched_matrix[i])));
			always @(posedge clk)
				if (reset | t_flash_clear)
					r_mem_sched_matrix[i] <= 'd0;
				else if (t_mem_alloc_entry[i])
					r_mem_sched_matrix[i] <= t_mem_sched_mask_valid;
				else if (|w_mem_sched_oldest_ready)
					r_mem_sched_matrix[i] <= r_mem_sched_matrix[i] & ~t_mem_select_entry;
		end
	endgenerate
	find_first_set #(2) ffs_mem_sched_select(
		.in(w_mem_sched_oldest_ready),
		.y(t_mem_sched_select_ptr)
	);
	always @(posedge clk) begin
		r_mem_ready <= (reset ? 1'b0 : |w_mem_sched_oldest_ready & !ds_done);
		mem_uop <= t_picked_mem_uop;
	end
	wire [63:0] w_agu_addr;
	mwidth_add agu(
		.A(t_mem_srcA),
		.B(mem_uop[220-:64]),
		.Y(w_agu_addr)
	);
	wire w_bad_16b_addr = &w_agu_addr[3:0];
	wire w_bad_32b_addr = &w_agu_addr[3:2] & |w_agu_addr[1:0];
	wire w_bad_64b_addr = w_agu_addr[3] & |w_agu_addr[2:0];
	always @(*) begin
		if (_sv2v_0)
			;
		t_mem_tail[162-:4] = 4'd4;
		t_mem_tail[230-:64] = w_agu_addr;
		t_mem_tail[144-:5] = mem_uop[28-:5];
		t_mem_tail[132] = 1'b0;
		t_mem_tail[139-:7] = mem_uop[228-:7];
		t_mem_tail[165] = 1'b0;
		t_mem_tail[166] = 1'b0;
		t_mem_tail[164] = 1'b0;
		t_mem_tail[158-:5] = mem_uop[97:93];
		t_mem_tail[131-:64] = 'd0;
		t_mem_tail[153] = 1'b0;
		t_mem_tail[152] = 1'b0;
		t_mem_tail[67-:64] = mem_uop[92-:64];
		t_mem_tail[151] = 1'b0;
		t_mem_tail[150-:5] = 5'd0;
		t_mem_tail[145] = 1'b0;
		t_mem_tail[163] = 1'b0;
		case (mem_uop[251-:7])
			7'd58: begin
				t_mem_tail[162-:4] = 4'd5;
				t_mem_tail[166] = 1'b1;
				t_mem_tail[132] = 1'b0;
			end
			7'd59: begin
				t_mem_tail[162-:4] = (w_bad_16b_addr ? 4'd10 : 4'd6);
				t_mem_tail[166] = ~w_bad_16b_addr;
				t_mem_tail[132] = 1'b0;
				t_mem_tail[153] = w_bad_16b_addr;
				t_mem_tail[152] = w_agu_addr[0];
			end
			7'd60: begin
				t_mem_tail[162-:4] = (w_bad_32b_addr ? 4'd10 : 4'd7);
				t_mem_tail[166] = ~w_bad_32b_addr;
				t_mem_tail[132] = 1'b0;
				t_mem_tail[153] = w_bad_32b_addr;
				t_mem_tail[152] = |w_agu_addr[1:0];
			end
			7'd61: begin
				t_mem_tail[162-:4] = (w_bad_64b_addr ? 4'd10 : 4'd13);
				t_mem_tail[166] = ~w_bad_64b_addr;
				t_mem_tail[132] = 1'b0;
				t_mem_tail[153] = w_bad_64b_addr;
				t_mem_tail[152] = |w_agu_addr[2:0];
			end
			7'd9: begin
				t_mem_tail[162-:4] = 4'd8;
				t_mem_tail[164] = 1'b1;
				t_mem_tail[132] = mem_uop[221];
				t_mem_tail[139-:7] = mem_uop[228-:7];
				t_mem_tail[153] = w_agu_addr[1:0] != 2'd0;
				t_mem_tail[152] = |w_agu_addr[1:0];
			end
			7'd10: begin
				t_mem_tail[162-:4] = 4'd9;
				t_mem_tail[164] = 1'b1;
				t_mem_tail[132] = mem_uop[221];
				t_mem_tail[139-:7] = mem_uop[228-:7];
				t_mem_tail[153] = w_agu_addr[2:0] != 3'd0;
				t_mem_tail[152] = |w_agu_addr[2:0];
			end
			7'd11: begin
				t_mem_tail[162-:4] = 4'd14;
				t_mem_tail[164] = 1'b1;
				t_mem_tail[132] = mem_uop[221];
				t_mem_tail[139-:7] = mem_uop[228-:7];
				t_mem_tail[153] = w_agu_addr[1:0] != 2'd0;
				t_mem_tail[152] = |w_agu_addr[1:0];
			end
			7'd12: begin
				t_mem_tail[162-:4] = 4'd15;
				t_mem_tail[164] = 1'b1;
				t_mem_tail[132] = mem_uop[221];
				t_mem_tail[139-:7] = mem_uop[228-:7];
				t_mem_tail[153] = w_agu_addr[2:0] != 3'd0;
				t_mem_tail[152] = |w_agu_addr[2:0];
			end
			7'd7: begin
				t_mem_tail[162-:4] = 4'd4;
				t_mem_tail[163] = 1'b1;
				t_mem_tail[132] = mem_uop[221];
				t_mem_tail[139-:7] = mem_uop[228-:7];
				t_mem_tail[153] = w_agu_addr[1:0] != 2'd0;
				t_mem_tail[152] = |w_agu_addr[1:0];
			end
			7'd8: begin
				t_mem_tail[162-:4] = 4'd12;
				t_mem_tail[163] = 1'b1;
				t_mem_tail[132] = mem_uop[221];
				t_mem_tail[139-:7] = mem_uop[228-:7];
				t_mem_tail[153] = w_agu_addr[2:0] != 3'd0;
				t_mem_tail[152] = |w_agu_addr[2:0];
			end
			7'd53: begin
				t_mem_tail[165] = 1'b1;
				t_mem_tail[162-:4] = (w_bad_32b_addr ? 4'd10 : 4'd4);
				t_mem_tail[132] = mem_uop[221];
				t_mem_tail[153] = w_bad_32b_addr;
				t_mem_tail[152] = |w_agu_addr[1:0];
			end
			7'd54: begin
				t_mem_tail[165] = 1'b1;
				t_mem_tail[162-:4] = (w_bad_32b_addr ? 4'd10 : 4'd11);
				t_mem_tail[132] = mem_uop[221];
				t_mem_tail[153] = w_bad_32b_addr;
				t_mem_tail[152] = |w_agu_addr[1:0];
			end
			7'd55: begin
				t_mem_tail[165] = 1'b1;
				t_mem_tail[162-:4] = (w_bad_64b_addr ? 4'd10 : 4'd12);
				t_mem_tail[132] = mem_uop[221];
				t_mem_tail[153] = w_bad_64b_addr;
				t_mem_tail[152] = |w_agu_addr[2:0];
			end
			7'd51: begin
				t_mem_tail[165] = 1'b1;
				t_mem_tail[162-:4] = 4'd0;
				t_mem_tail[132] = mem_uop[221];
			end
			7'd56: begin
				t_mem_tail[165] = 1'b1;
				t_mem_tail[162-:4] = 4'd1;
				t_mem_tail[132] = mem_uop[221];
			end
			7'd57: begin
				t_mem_tail[165] = 1'b1;
				t_mem_tail[162-:4] = 4'd3;
				t_mem_tail[132] = mem_uop[221];
				t_mem_tail[153] = w_agu_addr[0];
				t_mem_tail[152] = w_agu_addr[0];
			end
			7'd52: begin
				t_mem_tail[165] = 1'b1;
				t_mem_tail[162-:4] = (w_bad_16b_addr ? 4'd10 : 4'd2);
				t_mem_tail[132] = mem_uop[221];
				t_mem_tail[153] = w_bad_16b_addr;
				t_mem_tail[152] = w_agu_addr[0];
			end
			default:
				;
		endcase
	end
	always @(posedge clk) begin
		r_int_result <= t_result;
		r_int_result2 <= t_result2;
		r_mul_result <= t_mul_result;
		r_mem_result <= mem_rsp_load_data;
	end
	always @(*) begin
		if (_sv2v_0)
			;
		t_fwd_int_mem_srcA = (r_start_int & t_wr_int_prf) && (t_picked_mem_uop[244-:7] == int_uop[228-:7]);
		t_fwd_int_mem_srcB = (r_start_int & t_wr_int_prf) && (t_mem_dq[6-:7] == int_uop[228-:7]);
		t_fwd_int2_mem_srcA = (r_start_int2 & t_wr_int_prf2) && (t_picked_mem_uop[244-:7] == int_uop2[228-:7]);
		t_fwd_int2_mem_srcB = (r_start_int2 & t_wr_int_prf2) && (t_mem_dq[6-:7] == int_uop2[228-:7]);
		t_fwd_mem_mem_srcA = mem_rsp_dst_valid & (t_picked_mem_uop[244-:7] == mem_rsp_dst_ptr);
		t_fwd_mem_mem_srcB = mem_rsp_dst_valid & (t_mem_dq[6-:7] == mem_rsp_dst_ptr);
	end
	always @(posedge clk) begin
		r_fwd_int_mem_srcA <= t_fwd_int_mem_srcA;
		r_fwd_int_mem_srcB <= t_fwd_int_mem_srcB;
		r_fwd_int2_mem_srcA <= t_fwd_int2_mem_srcA;
		r_fwd_int2_mem_srcB <= t_fwd_int2_mem_srcB;
		r_fwd_mem_mem_srcA <= t_fwd_mem_mem_srcA;
		r_fwd_mem_mem_srcB <= t_fwd_mem_mem_srcB;
		r_fwd_int_srcA <= (r_start_int & t_wr_int_prf) & (t_picked_uop[244-:7] == int_uop[228-:7]);
		r_fwd_int_srcB <= (r_start_int & t_wr_int_prf) & (t_picked_uop[236-:7] == int_uop[228-:7]);
		r_fwd_mul_srcA <= t_mul_complete & (t_picked_uop[244-:7] == w_mul_prf_ptr);
		r_fwd_mul_srcB <= t_mul_complete & (t_picked_uop[236-:7] == w_mul_prf_ptr);
		r_fwd_int2_srcA <= (r_start_int2 & t_wr_int_prf2) & (t_picked_uop[244-:7] == int_uop2[228-:7]);
		r_fwd_int2_srcB <= (r_start_int2 & t_wr_int_prf2) & (t_picked_uop[236-:7] == int_uop2[228-:7]);
		r_fwd_int_srcA2 <= (r_start_int & t_wr_int_prf) & (t_picked_uop2[244-:7] == int_uop[228-:7]);
		r_fwd_int_srcB2 <= (r_start_int & t_wr_int_prf) & (t_picked_uop2[236-:7] == int_uop[228-:7]);
		r_fwd_mul_srcA2 <= t_mul_complete & (t_picked_uop2[244-:7] == w_mul_prf_ptr);
		r_fwd_mul_srcB2 <= t_mul_complete & (t_picked_uop2[236-:7] == w_mul_prf_ptr);
		r_fwd_int2_srcA2 <= (r_start_int2 & t_wr_int_prf2) & (t_picked_uop2[244-:7] == int_uop2[228-:7]);
		r_fwd_int2_srcB2 <= (r_start_int2 & t_wr_int_prf2) & (t_picked_uop2[236-:7] == int_uop2[228-:7]);
		r_fwd_mem_srcA <= mem_rsp_dst_valid & (t_picked_uop[244-:7] == mem_rsp_dst_ptr);
		r_fwd_mem_srcB <= mem_rsp_dst_valid & (t_picked_uop[236-:7] == mem_rsp_dst_ptr);
		r_fwd_mem_srcA2 <= mem_rsp_dst_valid & (t_picked_uop2[244-:7] == mem_rsp_dst_ptr);
		r_fwd_mem_srcB2 <= mem_rsp_dst_valid & (t_picked_uop2[236-:7] == mem_rsp_dst_ptr);
	end
	rf6r3w #(
		.WIDTH(64),
		.LG_DEPTH(7)
	) intprf(
		.clk(clk),
		.reset(reset),
		.rdptr0(t_picked_uop[244-:7]),
		.rdptr1(t_picked_uop[236-:7]),
		.rdptr2(t_picked_mem_uop[244-:7]),
		.rdptr3(t_mem_dq[6-:7]),
		.rdptr4(t_picked_uop2[244-:7]),
		.rdptr5(t_picked_uop2[236-:7]),
		.wrptr0((t_mul_complete ? w_mul_prf_ptr : (t_div_complete ? w_div_prf_ptr : int_uop[228-:7]))),
		.wrptr1(mem_rsp_dst_ptr),
		.wrptr2(int_uop2[228-:7]),
		.wen0((t_mul_complete | t_div_complete) | (r_start_int & t_wr_int_prf)),
		.wen1(mem_rsp_dst_valid),
		.wen2(r_start_int2 & t_wr_int_prf2),
		.wr0((t_mul_complete ? t_mul_result : (t_div_complete ? t_div_result : t_result))),
		.wr1(mem_rsp_load_data),
		.wr2(t_result2),
		.rd0(w_srcA),
		.rd1(w_srcB),
		.rd2(w_mem_srcA),
		.rd3(w_mem_srcB),
		.rd4(w_srcA_2),
		.rd5(w_srcB_2)
	);
	always @(posedge clk)
		if (reset) begin
			complete_valid_1 <= 1'b0;
			complete_valid_2 <= 1'b0;
		end
		else begin
			complete_valid_1 <= ((r_start_int & t_alu_valid) | t_mul_complete) | t_div_complete;
			complete_valid_2 <= r_start_int2;
		end
	always @(posedge clk) begin
		complete_bundle_2[141-:5] <= int_uop2[28-:5];
		complete_bundle_2[136] <= t_alu_valid2;
		complete_bundle_2[135] <= t_mispred_br2;
		complete_bundle_2[134-:64] <= t_pc_2;
		complete_bundle_2[69-:5] <= 5'd0;
		complete_bundle_2[64] <= 1'b0;
		complete_bundle_2[70] <= t_take_br2;
		complete_bundle_2[63-:64] <= t_result2;
	end
	always @(posedge clk)
		if (t_mul_complete || t_div_complete) begin
			complete_bundle_1[141-:5] <= (t_mul_complete ? t_rob_ptr_out : t_div_rob_ptr);
			complete_bundle_1[136] <= 1'b1;
			complete_bundle_1[135] <= 1'b0;
			complete_bundle_1[134-:64] <= 'd0;
			complete_bundle_1[69-:5] <= 5'd0;
			complete_bundle_1[64] <= 1'b0;
			complete_bundle_1[70] <= 1'b0;
			complete_bundle_1[63-:64] <= (t_mul_complete ? t_mul_result : t_div_result);
		end
		else begin
			complete_bundle_1[141-:5] <= int_uop[28-:5];
			complete_bundle_1[136] <= t_alu_valid;
			complete_bundle_1[135] <= t_mispred_br || t_has_cause;
			complete_bundle_1[134-:64] <= t_pc;
			complete_bundle_1[69-:5] <= t_cause;
			complete_bundle_1[64] <= t_has_cause;
			complete_bundle_1[70] <= t_take_br;
			complete_bundle_1[63-:64] <= t_result;
		end
	initial _sv2v_0 = 0;
endmodule

module l1d (
	clk,
	reset,
	priv,
	page_table_root,
	l2_probe_addr,
	l2_probe_val,
	l2_probe_ack,
	l1d_state,
	restart_complete,
	paging_active,
	clear_tlb,
	page_walk_req_valid,
	page_walk_req_va,
	page_walk_rsp_gnt,
	page_walk_rsp_valid,
	page_walk_rsp,
	head_of_rob_ptr,
	head_of_rob_ptr_valid,
	retired_rob_ptr_valid,
	retired_rob_ptr_two_valid,
	retired_rob_ptr,
	retired_rob_ptr_two,
	memq_empty,
	drain_ds_complete,
	dead_rob_mask,
	flush_req,
	flush_complete,
	flush_cl_req,
	flush_cl_addr,
	core_mem_va_req_valid,
	core_mem_va_req,
	core_store_data_valid,
	core_store_data,
	core_store_data_ack,
	core_mem_va_req_ack,
	core_mem_rsp,
	core_mem_rsp_valid,
	mem_req_valid,
	mem_req_uc,
	mem_req_addr,
	mem_req_store_data,
	mem_req_opcode,
	mem_rsp_valid,
	mem_rsp_load_data,
	mtimecmp,
	mtimecmp_val,
	cache_accesses,
	cache_hits,
	tlb_accesses,
	tlb_hits
);
	reg _sv2v_0;
	localparam L1D_NUM_SETS = 256;
	localparam L1D_CL_LEN = 16;
	localparam L1D_CL_LEN_BITS = 128;
	input wire clk;
	input wire reset;
	input wire [1:0] priv;
	input wire [63:0] page_table_root;
	input wire l2_probe_val;
	input wire [63:0] l2_probe_addr;
	output wire l2_probe_ack;
	output wire [3:0] l1d_state;
	input wire restart_complete;
	input wire paging_active;
	input wire clear_tlb;
	output wire page_walk_req_valid;
	output wire [63:0] page_walk_req_va;
	input wire page_walk_rsp_gnt;
	input wire page_walk_rsp_valid;
	input wire [71:0] page_walk_rsp;
	input wire [4:0] head_of_rob_ptr;
	input wire head_of_rob_ptr_valid;
	input wire retired_rob_ptr_valid;
	input wire retired_rob_ptr_two_valid;
	input wire [4:0] retired_rob_ptr;
	input wire [4:0] retired_rob_ptr_two;
	output reg memq_empty;
	input wire drain_ds_complete;
	input wire [31:0] dead_rob_mask;
	input wire flush_cl_req;
	input wire [63:0] flush_cl_addr;
	input wire flush_req;
	output wire flush_complete;
	input wire core_mem_va_req_valid;
	input wire [230:0] core_mem_va_req;
	input wire core_store_data_valid;
	input wire [68:0] core_store_data;
	output reg core_store_data_ack;
	output reg core_mem_va_req_ack;
	output wire [147:0] core_mem_rsp;
	output wire core_mem_rsp_valid;
	output wire mem_req_valid;
	output wire mem_req_uc;
	output wire [63:0] mem_req_addr;
	output wire [127:0] mem_req_store_data;
	output wire [3:0] mem_req_opcode;
	input wire mem_rsp_valid;
	input wire [127:0] mem_rsp_load_data;
	output wire [63:0] mtimecmp;
	output wire mtimecmp_val;
	output wire [63:0] cache_accesses;
	output wire [63:0] cache_hits;
	output wire [63:0] tlb_accesses;
	output wire [63:0] tlb_hits;
	localparam LG_WORDS_PER_CL = 2;
	localparam LG_DWORDS_PER_CL = 1;
	localparam WORDS_PER_CL = 4;
	localparam BYTES_PER_CL = 16;
	localparam N_TAG_BITS = 52;
	localparam IDX_START = 4;
	localparam IDX_STOP = 12;
	localparam WORD_START = 2;
	localparam WORD_STOP = 4;
	localparam DWORD_START = 3;
	localparam DWORD_STOP = 4;
	localparam N_MQ_ENTRIES = 8;
	reg r_got_req;
	reg r_last_wr;
	reg n_last_wr;
	reg r_wr_array;
	reg r_last_rd;
	reg n_last_rd;
	reg r_got_req2;
	reg r_last_wr2;
	reg n_last_wr2;
	reg r_last_rd2;
	reg n_last_rd2;
	reg rr_got_req;
	reg rr_last_wr;
	reg rr_is_retry;
	reg rr_did_reload;
	reg r_lock_cache;
	reg n_lock_cache;
	reg n_l2_probe_ack;
	reg r_l2_probe_ack;
	assign l2_probe_ack = r_l2_probe_ack;
	reg [3:0] r_n_inflight;
	reg [7:0] t_cache_idx;
	reg [7:0] r_cache_idx;
	reg [7:0] rr_cache_idx;
	reg [51:0] t_cache_tag;
	reg [51:0] r_cache_tag;
	wire [51:0] r_tag_out;
	reg [51:0] rr_cache_tag;
	wire r_valid_out;
	wire r_dirty_out;
	wire [127:0] r_array_out;
	reg [127:0] t_data;
	reg [127:0] t_data2;
	reg [7:0] t_cache_idx2;
	reg [7:0] r_cache_idx2;
	reg [51:0] t_cache_tag2;
	reg [51:0] r_cache_tag2;
	wire [51:0] r_tag_out2;
	wire r_valid_out2;
	wire r_dirty_out2;
	wire [127:0] r_array_out2;
	reg [7:0] t_miss_idx;
	reg [7:0] r_miss_idx;
	reg [63:0] t_miss_addr;
	reg [63:0] r_miss_addr;
	reg [7:0] t_array_wr_addr;
	reg [127:0] t_array_wr_data;
	reg [127:0] r_array_wr_data;
	reg t_array_wr_en;
	reg t_ack_ld_early;
	reg r_ack_ld_early;
	reg r_flush_req;
	reg n_flush_req;
	reg r_flush_cl_req;
	reg n_flush_cl_req;
	reg r_flush_complete;
	reg n_flush_complete;
	reg [127:0] t_shift;
	reg [127:0] t_shift_2;
	reg [127:0] t_store_shift;
	reg [127:0] t_store_mask;
	reg t_got_rd_retry;
	reg t_port2_hit_cache;
	reg t_mark_invalid;
	reg t_wr_array;
	reg t_wr_store;
	reg t_hit_cache;
	reg t_rsp_dst_valid;
	reg [63:0] t_rsp_data;
	reg t_hit_cache2;
	reg t_rsp_dst_valid2;
	reg [63:0] t_rsp_data2;
	reg [127:0] t_array_data;
	reg [63:0] t_addr;
	reg t_got_req;
	reg t_got_req2;
	reg t_replay_req2;
	reg t_tlb_xlat;
	reg n_pending_tlb_miss;
	reg r_pending_tlb_miss;
	reg n_pending_tlb_zero_page;
	reg r_pending_tlb_zero_page;
	reg t_got_miss;
	reg t_push_miss;
	reg t_mh_block;
	reg t_cm_block;
	wire t_cm_block2;
	reg t_cm_block_stall;
	reg r_must_forward;
	reg r_must_forward2;
	reg n_inhibit_write;
	reg r_inhibit_write;
	reg t_got_non_mem;
	reg r_got_non_mem;
	reg t_incr_busy;
	reg t_force_clear_busy;
	reg n_stall_store;
	reg r_stall_store;
	reg n_is_retry;
	reg r_is_retry;
	reg r_q_priority;
	reg n_q_priority;
	reg n_core_mem_rsp_valid;
	reg r_core_mem_rsp_valid;
	reg [147:0] n_core_mem_rsp;
	reg [147:0] r_core_mem_rsp;
	reg [230:0] n_req;
	reg [230:0] r_req;
	wire [230:0] t_req;
	reg [230:0] n_req2;
	reg [230:0] r_req2;
	reg [230:0] t_req2_pa;
	reg [230:0] r_mem_q [7:0];
	reg [3:0] r_mq_head_ptr;
	reg [3:0] n_mq_head_ptr;
	reg [3:0] r_mq_tail_ptr;
	reg [3:0] n_mq_tail_ptr;
	reg [3:0] t_mq_tail_ptr_plus_one;
	function [15:0] make_mask;
		input reg [230:0] r;
		reg [15:0] t_m;
		reg [15:0] m;
		reg b;
		reg s;
		reg w;
		reg d;
		begin
			b = ((r[162-:4] == 4'd5) || (r[162-:4] == 4'd0)) || (r[162-:4] == 4'd1);
			s = ((r[162-:4] == 4'd6) || (r[162-:4] == 4'd2)) || (r[162-:4] == 4'd3);
			w = (r[162-:4] == 4'd7) || (r[162-:4] == 4'd4);
			d = (r[162-:4] == 4'd13) || (r[162-:4] == 4'd12);
			t_m = (b ? 16'h0001 : (s ? 16'h0003 : (w ? 16'h000f : (d ? 16'h00ff : 16'hffff))));
			m = t_m << r[170:167];
			make_mask = m;
		end
	endfunction
	reg [15:0] t_mq_mask;
	reg [15:0] t_req_mask;
	always @(*) begin
		if (_sv2v_0)
			;
		t_mq_mask = make_mask(r_req2);
		t_req_mask = make_mask(core_mem_va_req);
	end
	reg [7:0] r_mq_addr_valid;
	reg [7:0] r_mq_addr [7:0];
	reg [15:0] r_mq_mask [7:0];
	reg [63:0] r_mq_full_addr [7:0];
	reg r_mq_is_load [7:0];
	reg r_mq_is_unaligned [7:0];
	reg [3:0] r_mq_op [7:0];
	reg [61:0] r_mq_word_addr [7:0];
	wire [15:0] w_store_byte_en;
	wire [230:0] t_mem_tail;
	reg [230:0] t_mem_head;
	reg mem_q_full;
	reg mem_q_empty;
	reg mem_q_almost_full;
	reg [3:0] r_state;
	reg [3:0] n_state;
	assign l1d_state = r_state;
	reg t_pop_mq;
	reg n_did_reload;
	reg r_did_reload;
	reg r_mem_req_valid;
	reg n_mem_req_valid;
	reg r_mem_req_uc;
	reg n_mem_req_uc;
	reg [63:0] r_mem_req_addr;
	reg [63:0] n_mem_req_addr;
	reg [127:0] r_mem_req_store_data;
	reg [127:0] n_mem_req_store_data;
	reg [3:0] r_mem_req_opcode;
	reg [3:0] n_mem_req_opcode;
	reg [63:0] n_cache_accesses;
	reg [63:0] r_cache_accesses;
	reg [63:0] n_cache_hits;
	reg [63:0] r_cache_hits;
	wire w_tlb_hit;
	wire w_tlb_dirty;
	wire w_tlb_writable;
	wire w_tlb_readable;
	wire w_tlb_user;
	wire w_zero_page;
	wire [63:0] w_tlb_pa;
	reg [63:0] r_tlb_addr;
	reg [63:0] n_tlb_addr;
	reg t_reload_tlb;
	reg n_page_walk_req_valid;
	reg r_page_walk_req_valid;
	reg r_page_walk_gnt;
	reg n_page_walk_gnt;
	reg n_flush_was_active;
	reg r_flush_was_active;
	reg [63:0] r_store_stalls;
	reg [63:0] n_store_stalls;
	reg [31:0] r_cycle;
	assign flush_complete = r_flush_complete;
	assign mem_req_addr = r_mem_req_addr;
	assign mem_req_store_data = r_mem_req_store_data;
	assign mem_req_opcode = r_mem_req_opcode;
	assign mem_req_valid = r_mem_req_valid;
	assign mem_req_uc = r_mem_req_uc;
	assign core_mem_rsp_valid = r_core_mem_rsp_valid;
	assign core_mem_rsp = r_core_mem_rsp;
	assign cache_accesses = r_cache_accesses;
	assign cache_hits = r_cache_hits;
	assign page_walk_req_valid = r_page_walk_req_valid;
	assign page_walk_req_va = r_tlb_addr;
	always @(posedge clk) r_cycle <= (reset ? 'd0 : r_cycle + 'd1);
	always @(posedge clk)
		if (reset) begin
			r_mq_head_ptr <= 'd0;
			r_mq_tail_ptr <= 'd0;
		end
		else begin
			r_mq_head_ptr <= n_mq_head_ptr;
			r_mq_tail_ptr <= n_mq_tail_ptr;
		end
	localparam N_ROB_ENTRIES = 32;
	reg [1:0] r_graduated [31:0];
	reg [31:0] r_rob_inflight;
	reg t_reset_graduated;
	always @(posedge clk)
		if (reset) begin : sv2v_autoblock_1
			integer i;
			for (i = 0; i < N_ROB_ENTRIES; i = i + 1)
				r_graduated[i] <= 2'b00;
		end
		else begin
			if (retired_rob_ptr_valid && (r_graduated[retired_rob_ptr] == 2'b01))
				r_graduated[retired_rob_ptr] <= 2'b10;
			if (retired_rob_ptr_two_valid && (r_graduated[retired_rob_ptr_two] == 2'b01))
				r_graduated[retired_rob_ptr_two] <= 2'b10;
			if (t_incr_busy)
				r_graduated[r_req2[144-:5]] <= 2'b01;
			if (t_reset_graduated)
				r_graduated[r_req[144-:5]] <= 2'b00;
			if (t_force_clear_busy)
				r_graduated[t_mem_head[144-:5]] <= 2'b00;
		end
	always @(posedge clk)
		if (reset)
			r_n_inflight <= 'd0;
		else if ((core_mem_va_req_valid && core_mem_va_req_ack) && !core_mem_rsp_valid)
			r_n_inflight <= r_n_inflight + 'd1;
		else if (!(core_mem_va_req_valid && core_mem_va_req_ack) && core_mem_rsp_valid)
			r_n_inflight <= r_n_inflight - 'd1;
	always @(*) begin
		if (_sv2v_0)
			;
		n_mq_head_ptr = r_mq_head_ptr;
		n_mq_tail_ptr = r_mq_tail_ptr;
		t_mq_tail_ptr_plus_one = r_mq_tail_ptr + 'd1;
		if (t_push_miss)
			n_mq_tail_ptr = r_mq_tail_ptr + 'd1;
		if (t_pop_mq)
			n_mq_head_ptr = r_mq_head_ptr + 'd1;
		t_mem_head = r_mem_q[r_mq_head_ptr[2:0]];
		mem_q_empty = r_mq_head_ptr == r_mq_tail_ptr;
		mem_q_full = (r_mq_head_ptr != r_mq_tail_ptr) && (r_mq_head_ptr[2:0] == r_mq_tail_ptr[2:0]);
		mem_q_almost_full = (r_mq_head_ptr != t_mq_tail_ptr_plus_one) && (r_mq_head_ptr[2:0] == t_mq_tail_ptr_plus_one[2:0]);
	end
	always @(posedge clk)
		if (reset)
			r_rob_inflight <= 'd0;
		else begin
			if ((r_got_req2 && !drain_ds_complete) && t_push_miss) begin
				if (r_rob_inflight[r_req2[144-:5]] == 1'b1)
					$display("entry %d should not be inflight\n", r_req2[144-:5]);
				r_rob_inflight[r_req2[144-:5]] <= 1'b1;
			end
			if ((((r_got_req && r_valid_out) && (r_tag_out == r_cache_tag)) && !r_req[145]) || t_ack_ld_early) begin
				if (r_rob_inflight[r_req[144-:5]] == 1'b0)
					$display("huh %d should be inflight....\n", r_req[144-:5]);
				r_rob_inflight[r_req[144-:5]] <= 1'b0;
			end
			if (t_force_clear_busy)
				r_rob_inflight[t_mem_head[144-:5]] <= 1'b0;
		end
	always @(posedge clk)
		if (t_push_miss) begin
			r_mem_q[r_mq_tail_ptr[2:0]] <= t_req2_pa;
			r_mq_addr[r_mq_tail_ptr[2:0]] <= r_req2[178:171];
			r_mq_mask[r_mq_tail_ptr[2:0]] <= t_mq_mask & {16 {r_req2[166]}};
			r_mq_op[r_mq_tail_ptr[2:0]] <= r_req2[162-:4];
			r_mq_is_load[r_mq_tail_ptr[2:0]] <= r_req2[165];
			r_mq_is_unaligned[r_mq_tail_ptr[2:0]] <= r_req2[152];
			r_mq_full_addr[r_mq_tail_ptr[2:0]] <= r_req2[230-:64];
			r_mq_word_addr[r_mq_tail_ptr[2:0]] <= r_req2[230:169];
		end
	always @(posedge clk)
		if (reset)
			r_mq_addr_valid <= 'd0;
		else begin
			if (t_push_miss)
				r_mq_addr_valid[r_mq_tail_ptr[2:0]] <= 1'b1;
			if (t_pop_mq)
				r_mq_addr_valid[r_mq_head_ptr[2:0]] <= 1'b0;
		end
	wire [7:0] w_hit_busy_addrs;
	reg [7:0] r_hit_busy_addrs;
	reg r_hit_busy_addr;
	wire [7:0] w_hit_busy_addrs2;
	wire [7:0] w_addr_intersect;
	reg [7:0] r_hit_busy_addrs2;
	reg r_hit_busy_addr2;
	wire r_hit_busy_word_addr2;
	wire [7:0] w_unaligned_in_mq;
	reg r_any_unaligned;
	genvar _gv_i_1;
	generate
		for (_gv_i_1 = 0; _gv_i_1 < N_MQ_ENTRIES; _gv_i_1 = _gv_i_1 + 1) begin : genblk1
			localparam i = _gv_i_1;
			assign w_hit_busy_addrs[i] = (t_pop_mq && (r_mq_head_ptr[2:0] == i) ? 1'b0 : (r_mq_addr_valid[i] ? r_mq_addr[i] == t_cache_idx : 1'b0));
			assign w_addr_intersect[i] = |(r_mq_mask[i] & t_req_mask);
			assign w_hit_busy_addrs2[i] = (r_mq_addr_valid[i] ? (r_mq_addr[i] == t_cache_idx2) & w_addr_intersect[i] : 1'b0);
			assign w_unaligned_in_mq[i] = (r_mq_addr_valid[i] ? r_mq_is_unaligned[i] : 1'b0);
		end
	endgenerate
	always @(posedge clk) begin
		r_hit_busy_addr <= (reset ? 1'b0 : |w_hit_busy_addrs);
		r_hit_busy_addr2 <= (reset ? 1'b0 : |w_hit_busy_addrs2);
		r_hit_busy_addrs <= (t_got_req ? w_hit_busy_addrs : {N_MQ_ENTRIES {1'b1}});
		r_hit_busy_addrs2 <= (t_got_req2 ? w_hit_busy_addrs2 : {N_MQ_ENTRIES {1'b1}});
		r_any_unaligned <= (reset ? 1'b0 : |w_unaligned_in_mq | core_mem_va_req[152]);
	end
	always @(posedge clk) r_array_wr_data <= t_array_data;
	always @(posedge clk)
		if (reset) begin
			r_l2_probe_ack <= 1'b0;
			r_page_walk_req_valid <= 1'b0;
			r_page_walk_gnt <= 1'b0;
			r_flush_was_active <= 1'b0;
			r_pending_tlb_miss <= 1'b0;
			r_pending_tlb_zero_page <= 1'b0;
			r_tlb_addr <= 'd0;
			r_ack_ld_early <= 1'b0;
			r_did_reload <= 1'b0;
			r_stall_store <= 1'b0;
			r_is_retry <= 1'b0;
			r_flush_complete <= 1'b0;
			r_flush_req <= 1'b0;
			r_flush_cl_req <= 1'b0;
			r_cache_idx <= 'd0;
			r_cache_tag <= 'd0;
			r_cache_idx2 <= 'd0;
			r_cache_tag2 <= 'd0;
			rr_cache_idx <= 'd0;
			rr_cache_tag <= 'd0;
			r_miss_addr <= 'd0;
			r_miss_idx <= 'd0;
			r_got_req <= 1'b0;
			r_got_req2 <= 1'b0;
			rr_got_req <= 1'b0;
			r_lock_cache <= 1'b0;
			rr_is_retry <= 1'b0;
			rr_did_reload <= 1'b0;
			rr_last_wr <= 1'b0;
			r_wr_array <= 1'b0;
			r_got_non_mem <= 1'b0;
			r_last_wr <= 1'b0;
			r_last_rd <= 1'b0;
			r_last_wr2 <= 1'b0;
			r_last_rd2 <= 1'b0;
			r_state <= 4'd0;
			r_mem_req_valid <= 1'b0;
			r_mem_req_uc <= 1'b0;
			r_mem_req_addr <= 'd0;
			r_mem_req_store_data <= 'd0;
			r_mem_req_opcode <= 'd0;
			r_core_mem_rsp_valid <= 1'b0;
			r_cache_hits <= 'd0;
			r_cache_accesses <= 'd0;
			r_store_stalls <= 'd0;
			r_inhibit_write <= 1'b0;
			memq_empty <= 1'b1;
			r_q_priority <= 1'b0;
			r_must_forward <= 1'b0;
			r_must_forward2 <= 1'b0;
		end
		else begin
			r_l2_probe_ack <= n_l2_probe_ack;
			r_page_walk_req_valid <= n_page_walk_req_valid;
			r_page_walk_gnt <= n_page_walk_gnt;
			r_flush_was_active <= n_flush_was_active;
			r_pending_tlb_miss <= n_pending_tlb_miss;
			r_pending_tlb_zero_page <= n_pending_tlb_zero_page;
			r_tlb_addr <= n_tlb_addr;
			r_ack_ld_early <= t_ack_ld_early;
			r_did_reload <= n_did_reload;
			r_stall_store <= n_stall_store;
			r_is_retry <= n_is_retry;
			r_flush_complete <= n_flush_complete;
			r_flush_req <= n_flush_req;
			r_flush_cl_req <= n_flush_cl_req;
			r_cache_idx <= t_cache_idx;
			r_cache_tag <= t_cache_tag;
			r_cache_idx2 <= t_cache_idx2;
			r_cache_tag2 <= t_cache_tag2;
			rr_cache_idx <= r_cache_idx;
			rr_cache_tag <= r_cache_tag;
			r_miss_idx <= t_miss_idx;
			r_miss_addr <= t_miss_addr;
			r_got_req <= t_got_req;
			r_got_req2 <= t_got_req2 | t_replay_req2;
			rr_got_req <= r_got_req;
			r_lock_cache <= n_lock_cache;
			rr_is_retry <= r_is_retry;
			rr_did_reload <= r_did_reload;
			rr_last_wr <= r_last_wr;
			r_wr_array <= t_wr_array;
			r_got_non_mem <= t_got_non_mem;
			r_last_wr <= n_last_wr;
			r_last_rd <= n_last_rd;
			r_last_wr2 <= n_last_wr2;
			r_last_rd2 <= n_last_rd2;
			r_state <= n_state;
			r_mem_req_valid <= n_mem_req_valid;
			r_mem_req_uc <= n_mem_req_uc;
			r_mem_req_addr <= n_mem_req_addr;
			r_mem_req_store_data <= n_mem_req_store_data;
			r_mem_req_opcode <= n_mem_req_opcode;
			r_core_mem_rsp_valid <= n_core_mem_rsp_valid;
			r_cache_hits <= n_cache_hits;
			r_cache_accesses <= n_cache_accesses;
			r_store_stalls <= n_store_stalls;
			r_inhibit_write <= n_inhibit_write;
			memq_empty <= (((((mem_q_empty && drain_ds_complete) && !core_mem_va_req_valid) && !t_got_req) && !t_got_req2) && !t_push_miss) && (r_n_inflight == 'd0);
			r_q_priority <= n_q_priority;
			r_must_forward <= t_mh_block & t_pop_mq;
			r_must_forward2 <= t_cm_block & core_mem_va_req_ack;
		end
	always @(posedge clk) begin
		r_req <= n_req;
		r_req2 <= n_req2;
		r_core_mem_rsp <= n_core_mem_rsp;
	end
	always @(*) begin
		if (_sv2v_0)
			;
		t_array_wr_addr = (mem_rsp_valid ? r_mem_req_addr[11:IDX_START] : r_cache_idx);
		t_array_wr_data = (mem_rsp_valid ? mem_rsp_load_data : t_store_shift);
		t_array_wr_en = (mem_rsp_valid && !((r_state == 4'd13) || (r_state == 4'd14))) || t_wr_array;
	end
	ram2r1w #(
		.WIDTH(N_TAG_BITS),
		.LG_DEPTH(8)
	) dc_tag(
		.clk(clk),
		.rd_addr0(t_cache_idx),
		.rd_addr1(t_cache_idx2),
		.wr_addr(r_mem_req_addr[11:IDX_START]),
		.wr_data(r_mem_req_addr[63:IDX_STOP]),
		.wr_en(mem_rsp_valid & !((r_state == 4'd13) | (r_state == 4'd14))),
		.rd_data0(r_tag_out),
		.rd_data1(r_tag_out2)
	);
	ram2r1w_l1d_data #(.LG_DEPTH(8)) dc_data(
		.clk(clk),
		.rd_addr0(t_cache_idx),
		.rd_addr1(t_cache_idx2),
		.wr_addr(t_array_wr_addr),
		.wr_data(t_array_wr_data),
		.wr_en(t_array_wr_en),
		.wr_byte_en(w_store_byte_en),
		.rd_data0(r_array_out),
		.rd_data1(r_array_out2)
	);
	reg t_dirty_value;
	reg t_write_dirty_en;
	reg [7:0] t_dirty_wr_addr;
	always @(*) begin
		if (_sv2v_0)
			;
		t_dirty_value = 1'b0;
		t_write_dirty_en = 1'b0;
		t_dirty_wr_addr = r_cache_idx;
		if (t_mark_invalid)
			t_write_dirty_en = 1'b1;
		else if (mem_rsp_valid & !((r_state == 4'd13) | (r_state == 4'd14))) begin
			t_dirty_wr_addr = r_mem_req_addr[11:IDX_START];
			t_write_dirty_en = 1'b1;
		end
		else if (t_wr_array) begin
			t_dirty_value = 1'b1;
			t_write_dirty_en = 1'b1;
		end
	end
	ram2r1w #(
		.WIDTH(1),
		.LG_DEPTH(8)
	) dc_dirty(
		.clk(clk),
		.rd_addr0(t_cache_idx),
		.rd_addr1(t_cache_idx2),
		.wr_addr(t_dirty_wr_addr),
		.wr_data(t_dirty_value),
		.wr_en(t_write_dirty_en),
		.rd_data0(r_dirty_out),
		.rd_data1(r_dirty_out2)
	);
	reg t_valid_value;
	reg t_write_valid_en;
	reg [7:0] t_valid_wr_addr;
	always @(*) begin
		if (_sv2v_0)
			;
		t_valid_value = 1'b0;
		t_write_valid_en = 1'b0;
		t_valid_wr_addr = r_cache_idx;
		if (t_mark_invalid)
			t_write_valid_en = 1'b1;
		else if (mem_rsp_valid & !((r_state == 4'd13) | (r_state == 4'd14))) begin
			t_valid_wr_addr = r_mem_req_addr[11:IDX_START];
			t_valid_value = !r_inhibit_write;
			t_write_valid_en = 1'b1;
		end
	end
	ram2r1w #(
		.WIDTH(1),
		.LG_DEPTH(8)
	) dc_valid(
		.clk(clk),
		.rd_addr0(t_cache_idx),
		.rd_addr1(t_cache_idx2),
		.wr_addr(t_valid_wr_addr),
		.wr_data(t_valid_value),
		.wr_en(t_write_valid_en),
		.rd_data0(r_valid_out),
		.rd_data1(r_valid_out2)
	);
	tlb #(.LG_N(5)) dtlb(
		.clk(clk),
		.reset(reset),
		.priv(priv),
		.clear(clear_tlb),
		.active(paging_active),
		.req(t_tlb_xlat),
		.va(n_tlb_addr),
		.pa(w_tlb_pa),
		.hit(w_tlb_hit),
		.dirty(w_tlb_dirty),
		.readable(w_tlb_readable),
		.writable(w_tlb_writable),
		.user(w_tlb_user),
		.zero_page(w_zero_page),
		.tlb_hits(tlb_hits),
		.tlb_accesses(tlb_accesses),
		.replace_va(r_tlb_addr),
		.replace(t_reload_tlb),
		.page_walk_rsp(page_walk_rsp)
	);
	reg t_wr_link_reg;
	reg r_paging_active;
	reg [63:0] n_link_reg;
	reg [63:0] r_link_reg;
	reg n_link_reg_val;
	reg r_link_reg_val;
	always @(posedge clk) r_paging_active <= (reset ? 1'b0 : paging_active);
	wire w_paging_toggle = r_paging_active ^ paging_active;
	always @(posedge clk)
		if (reset)
			r_link_reg_val <= 1'b0;
		else
			r_link_reg_val <= n_link_reg_val;
	always @(posedge clk)
		if (reset)
			r_link_reg <= 64'd0;
		else if (w_paging_toggle)
			r_link_reg <= 'd0;
		else if (t_wr_link_reg)
			r_link_reg <= n_link_reg;
	always @(*) begin
		if (_sv2v_0)
			;
		t_data2 = (r_got_req2 && r_must_forward2 ? r_array_wr_data : r_array_out2);
		t_hit_cache2 = ((r_valid_out2 && (r_tag_out2 == w_tlb_pa[63:IDX_STOP])) && r_got_req2) && (r_state == 4'd2);
		t_rsp_dst_valid2 = 1'b0;
		t_rsp_data2 = 'd0;
		t_shift_2 = t_data2 >> {r_req2[170:167], 3'd0};
		case (r_req2[162-:4])
			4'd0: begin
				t_rsp_data2 = {{56 {t_shift_2[7]}}, t_shift_2[7:0]};
				t_rsp_dst_valid2 = r_req2[132] & t_hit_cache2;
			end
			4'd1: begin
				t_rsp_data2 = {56'd0, t_shift_2[7:0]};
				t_rsp_dst_valid2 = r_req2[132] & t_hit_cache2;
			end
			4'd2: begin
				t_rsp_data2 = {{48 {t_shift_2[15]}}, t_shift_2[15:0]};
				t_rsp_dst_valid2 = r_req2[132] & t_hit_cache2;
			end
			4'd3: begin
				t_rsp_data2 = {48'd0, t_shift_2[15:0]};
				t_rsp_dst_valid2 = r_req2[132] & t_hit_cache2;
			end
			4'd4: begin
				t_rsp_data2 = {{32 {t_shift_2[31]}}, t_shift_2[31:0]};
				t_rsp_dst_valid2 = r_req2[132] & t_hit_cache2;
			end
			4'd11: begin
				t_rsp_data2 = {32'd0, t_shift_2[31:0]};
				t_rsp_dst_valid2 = r_req2[132] & t_hit_cache2;
			end
			4'd12: begin
				t_rsp_data2 = t_shift_2[63:0];
				t_rsp_dst_valid2 = r_req2[132] & t_hit_cache2;
			end
			default:
				;
		endcase
	end
	wire w_store32 = ((r_req[162-:4] == 4'd7) || (r_req[162-:4] == 4'd14)) || (r_req[162-:4] == 4'd8);
	wire w_store64 = ((r_req[162-:4] == 4'd13) || (r_req[162-:4] == 4'd15)) || (r_req[162-:4] == 4'd9);
	wire [63:0] w_store_mask = (r_req[162-:4] == 4'd5 ? 64'h00000000000000ff : (r_req[162-:4] == 4'd6 ? 64'h000000000000ffff : (w_store32 ? 64'h00000000ffffffff : (w_store64 ? 64'hffffffffffffffff : 'd0))));
	reg [31:0] t_amo32_data;
	reg [63:0] t_amo64_data;
	reg [63:0] r_mtimecmp;
	reg r_mtimecmp_val;
	assign mtimecmp = r_mtimecmp;
	assign mtimecmp_val = r_mtimecmp_val;
	always @(posedge clk)
		if (reset) begin
			r_mtimecmp <= 64'd0;
			r_mtimecmp_val <= 1'b0;
		end
		else begin
			r_mtimecmp_val <= t_wr_store && (r_req[230-:64] == 64'h0000000040004000);
			r_mtimecmp <= r_req[131-:64];
		end
	wire w_match_link = ({r_req[230:171], 4'd0} == r_link_reg) & r_link_reg_val;
	always @(*) begin
		if (_sv2v_0)
			;
		t_data = (mem_rsp_valid ? mem_rsp_load_data : (r_got_req && r_must_forward ? r_array_wr_data : r_array_out));
		t_hit_cache = (((r_valid_out && (r_tag_out == r_cache_tag)) && r_got_req) && (r_state == 4'd2)) && (r_req[145] == 1'b0);
		t_array_data = 'd0;
		t_wr_array = 1'b0;
		t_wr_store = 1'b0;
		t_rsp_dst_valid = 1'b0;
		t_rsp_data = 'd0;
		t_shift = t_data >> {r_req[170:167], 3'd0};
		t_store_shift = {64'd0, r_req[131-:64]} << {r_req[170:167], 3'd0};
		t_store_mask = {64'd0, w_store_mask} << {r_req[170:167], 3'd0};
		t_amo32_data = 32'hdeadbeef;
		t_amo64_data = 64'hd0debabefacebeef;
		t_wr_link_reg = 1'b0;
		n_link_reg = r_link_reg;
		n_link_reg_val = r_link_reg_val;
		case (r_req[158-:5])
			5'd0: begin
				t_amo32_data = t_shift[31:0] + r_req[99:68];
				t_amo64_data = t_shift[63:0] + r_req[131:68];
			end
			5'd1: begin
				t_amo32_data = r_req[99:68];
				t_amo64_data = r_req[131:68];
			end
			5'd4: begin
				t_amo32_data = t_shift[31:0] ^ r_req[99:68];
				t_amo64_data = t_shift[63:0] ^ r_req[131:68];
			end
			5'd8: begin
				t_amo32_data = t_shift[31:0] | r_req[99:68];
				t_amo64_data = t_shift[63:0] | r_req[131:68];
			end
			5'd12: begin
				t_amo32_data = t_shift[31:0] & r_req[99:68];
				t_amo64_data = t_shift[63:0] & r_req[131:68];
			end
			5'd28: begin
				t_amo32_data = (t_shift[31:0] < r_req[99:68] ? r_req[99:68] : t_shift[31:0]);
				t_amo64_data = (t_shift[63:0] < r_req[131:68] ? r_req[131:68] : t_shift[63:0]);
			end
			default:
				;
		endcase
		case (r_req[162-:4])
			4'd0: begin
				t_rsp_data = {{56 {t_shift[7]}}, t_shift[7:0]};
				t_rsp_dst_valid = r_req[132] & t_hit_cache;
			end
			4'd1: begin
				t_rsp_data = {56'd0, t_shift[7:0]};
				t_rsp_dst_valid = r_req[132] & t_hit_cache;
			end
			4'd2: begin
				t_rsp_data = {{48 {t_shift[15]}}, t_shift[15:0]};
				t_rsp_dst_valid = r_req[132] & t_hit_cache;
			end
			4'd3: begin
				t_rsp_data = {48'd0, t_shift[15:0]};
				t_rsp_dst_valid = r_req[132] & t_hit_cache;
			end
			4'd4: begin
				t_rsp_data = {{32 {t_shift[31]}}, t_shift[31:0]};
				t_rsp_dst_valid = r_req[132] & t_hit_cache;
				t_wr_link_reg = r_req[163];
				n_link_reg = {r_req[230:171], 4'd0};
				n_link_reg_val = r_req[163];
			end
			4'd11: begin
				t_rsp_data = {32'd0, t_shift[31:0]};
				t_rsp_dst_valid = r_req[132] & t_hit_cache;
			end
			4'd12: begin
				t_rsp_data = t_shift[63:0];
				t_rsp_dst_valid = r_req[132] & t_hit_cache;
				t_wr_link_reg = r_req[163];
				n_link_reg = {r_req[230:171], 4'd0};
				n_link_reg_val = r_req[163];
			end
			4'd5: begin
				t_array_data = (t_store_shift & t_store_mask) | (~t_store_mask & t_data);
				t_wr_store = t_hit_cache && (r_is_retry || r_did_reload);
			end
			4'd6: begin
				t_array_data = (t_store_shift & t_store_mask) | (~t_store_mask & t_data);
				t_wr_store = t_hit_cache && (r_is_retry || r_did_reload);
			end
			4'd7: begin
				t_array_data = (t_store_shift & t_store_mask) | (~t_store_mask & t_data);
				t_wr_store = t_hit_cache && (r_is_retry || r_did_reload);
			end
			4'd13: begin
				t_array_data = (t_store_shift & t_store_mask) | (~t_store_mask & t_data);
				t_wr_store = t_hit_cache && (r_is_retry || r_did_reload);
			end
			4'd9: begin
				t_rsp_data = {63'd0, ~w_match_link};
				t_array_data = (t_store_shift & t_store_mask) | (~t_store_mask & t_data);
				t_wr_store = (w_match_link && t_hit_cache) && ((r_is_retry || r_did_reload) & !r_req[151]);
				t_rsp_dst_valid = r_req[132] & t_hit_cache;
				n_link_reg_val = 1'b0;
			end
			4'd8: begin
				t_rsp_data = {63'd0, ~w_match_link};
				t_array_data = (t_store_shift & t_store_mask) | (~t_store_mask & t_data);
				t_wr_store = (w_match_link && t_hit_cache) && ((r_is_retry || r_did_reload) & !r_req[151]);
				t_rsp_dst_valid = r_req[132] & t_hit_cache;
				n_link_reg_val = 1'b0;
			end
			4'd14: begin
				t_rsp_data = {{32 {t_shift[31]}}, t_shift[31:0]};
				t_rsp_dst_valid = r_req[132] & t_hit_cache;
				t_store_shift = {96'd0, t_amo32_data} << {r_req[170:167], 3'd0};
				t_array_data = (t_store_shift & t_store_mask) | (~t_store_mask & t_data);
				t_wr_store = t_hit_cache && ((r_is_retry || r_did_reload) & !r_req[151]);
			end
			4'd15: begin
				t_rsp_data = t_shift[63:0];
				t_rsp_dst_valid = r_req[132] & t_hit_cache;
				t_store_shift = {64'd0, t_amo64_data} << {r_req[170:167], 3'd0};
				t_array_data = (t_store_shift & t_store_mask) | (~t_store_mask & t_data);
				t_wr_store = t_hit_cache && ((r_is_retry || r_did_reload) & !r_req[151]);
			end
			default:
				;
		endcase
		t_wr_array = t_wr_store;
	end
	genvar _gv_i_2;
	generate
		for (_gv_i_2 = 0; _gv_i_2 < BYTES_PER_CL; _gv_i_2 = _gv_i_2 + 1) begin : genblk2
			localparam i = _gv_i_2;
			assign w_store_byte_en[i] = (mem_rsp_valid ? 1'b1 : t_wr_array & t_store_mask[i * 8]);
		end
	endgenerate
	wire w_st_amo_grad = (t_mem_head[166] ? r_graduated[t_mem_head[144-:5]] == 2'b10 : 1'b1);
	wire w_tlb_st_exc = ((w_tlb_hit & paging_active) & (r_req2[166] | r_req2[164])) & !w_tlb_writable;
	wire w_tlb_st_not_dirty = (((w_tlb_hit & paging_active) & (r_req2[166] | r_req2[164])) & w_tlb_writable) & !w_tlb_dirty;
	wire w_flush_hit = (r_tag_out == l2_probe_addr[63:IDX_STOP]) & r_valid_out;
	wire w_uncachable = ((w_tlb_pa >= 64'h0000000040500000) && (w_tlb_pa < 64'h0000000040510000)) && 1'b0;
	always @(*) begin
		if (_sv2v_0)
			;
		n_flush_was_active = r_flush_was_active;
		n_page_walk_gnt = r_page_walk_gnt | page_walk_rsp_gnt;
		n_l2_probe_ack = 1'b0;
		t_reload_tlb = 1'b0;
		n_page_walk_req_valid = 1'b0;
		n_tlb_addr = r_tlb_addr;
		t_ack_ld_early = 1'b0;
		t_got_rd_retry = 1'b0;
		t_port2_hit_cache = r_valid_out2 && (r_tag_out2 == w_tlb_pa[63:IDX_STOP]);
		n_state = r_state;
		t_miss_idx = r_miss_idx;
		t_miss_addr = r_miss_addr;
		t_cache_idx = 'd0;
		t_cache_tag = 'd0;
		t_cache_idx2 = 'd0;
		t_cache_tag2 = 'd0;
		t_got_req = 1'b0;
		t_got_req2 = 1'b0;
		t_replay_req2 = 1'b0;
		t_tlb_xlat = 1'b0;
		n_pending_tlb_miss = r_pending_tlb_miss;
		n_pending_tlb_zero_page = r_pending_tlb_zero_page;
		t_got_non_mem = 1'b0;
		n_last_wr = 1'b0;
		n_last_rd = 1'b0;
		n_last_wr2 = 1'b0;
		n_last_rd2 = 1'b0;
		t_got_miss = 1'b0;
		t_push_miss = 1'b0;
		n_req = r_req;
		n_req2 = r_req2;
		t_req2_pa = r_req2;
		core_mem_va_req_ack = 1'b0;
		core_store_data_ack = 1'b0;
		n_mem_req_valid = 1'b0;
		n_mem_req_uc = 1'b0;
		n_mem_req_addr = r_mem_req_addr;
		n_mem_req_store_data = r_mem_req_store_data;
		n_mem_req_opcode = r_mem_req_opcode;
		t_pop_mq = 1'b0;
		n_core_mem_rsp_valid = 1'b0;
		n_core_mem_rsp[147-:64] = r_req[230-:64];
		n_core_mem_rsp[83-:64] = r_req[230-:64];
		n_core_mem_rsp[19-:5] = r_req[144-:5];
		n_core_mem_rsp[14-:7] = r_req[139-:7];
		n_core_mem_rsp[7] = 1'b0;
		n_core_mem_rsp[1] = 1'b0;
		n_core_mem_rsp[0] = 1'b0;
		n_core_mem_rsp[6-:5] = 5'd0;
		n_cache_accesses = r_cache_accesses;
		n_cache_hits = r_cache_hits;
		n_store_stalls = r_store_stalls;
		n_flush_req = r_flush_req | flush_req;
		n_flush_cl_req = r_flush_cl_req | l2_probe_val;
		n_flush_complete = 1'b0;
		t_addr = 'd0;
		n_inhibit_write = r_inhibit_write;
		t_mark_invalid = 1'b0;
		n_is_retry = 1'b0;
		t_reset_graduated = 1'b0;
		t_force_clear_busy = 1'b0;
		t_incr_busy = 1'b0;
		n_stall_store = 1'b0;
		n_q_priority = !r_q_priority;
		n_did_reload = 1'b0;
		n_lock_cache = r_lock_cache;
		t_mh_block = (r_got_req && r_last_wr) && (r_cache_idx == t_mem_head[178:171]);
		t_cm_block = (r_got_req && r_last_wr) && (r_cache_idx == core_mem_va_req[178:171]);
		t_cm_block_stall = t_cm_block && !(r_did_reload || r_is_retry);
		case (r_state)
			4'd0: begin
				n_state = 4'd1;
				t_cache_idx = 'd0;
			end
			4'd1: begin
				t_cache_idx = r_cache_idx + 'd1;
				t_mark_invalid = 1'b1;
				if (r_cache_idx == 255) begin
					n_state = 4'd2;
					n_flush_complete = 1'b1;
				end
				else
					t_cache_idx = r_cache_idx + 'd1;
			end
			4'd2: begin
				if (r_got_req2) begin
					n_core_mem_rsp[147-:64] = r_req2[230-:64];
					n_core_mem_rsp[19-:5] = r_req2[144-:5];
					n_core_mem_rsp[14-:7] = r_req2[139-:7];
					t_req2_pa[230-:64] = w_tlb_pa;
					t_req2_pa[145] = w_uncachable;
					if (r_pending_tlb_miss) begin
						n_pending_tlb_miss = 1'b0;
						n_pending_tlb_zero_page = 1'b0;
					end
					if (drain_ds_complete || (r_req2[162-:4] == 4'd10)) begin
						n_core_mem_rsp[7] = r_req2[132];
						n_core_mem_rsp[1] = r_req2[151];
						n_core_mem_rsp[6-:5] = r_req2[150-:5];
						n_core_mem_rsp[83-:64] = r_req2[230-:64];
						n_core_mem_rsp_valid = 1'b1;
					end
					else if (!w_tlb_hit) begin
						n_pending_tlb_miss = 1'b1;
						n_pending_tlb_zero_page = w_zero_page;
						if (r_pending_tlb_miss)
							$stop;
					end
					else if (w_tlb_st_exc) begin
						$display("store exception for pc %x, addr %x, cycle %d", r_req2[67-:64], r_req2[230-:64], r_cycle);
						n_core_mem_rsp[7] = r_req2[132];
						n_core_mem_rsp[1] = 1'b1;
						n_core_mem_rsp[6-:5] = 5'd15;
						n_core_mem_rsp[83-:64] = r_req2[230-:64];
						n_core_mem_rsp_valid = 1'b1;
					end
					else if (w_uncachable & !r_req2[166])
						t_push_miss = 1'b1;
					else if (r_req2[164] || r_req2[163])
						t_push_miss = 1'b1;
					else if (r_req2[166]) begin
						t_push_miss = 1'b1;
						t_incr_busy = 1'b1;
						n_stall_store = 1'b1;
						n_core_mem_rsp[7] = 1'b0;
						if (t_port2_hit_cache)
							n_cache_hits = r_cache_hits + 'd1;
						n_core_mem_rsp_valid = 1'b1;
						n_core_mem_rsp[1] = r_req2[153];
						n_core_mem_rsp[0] = w_tlb_st_not_dirty;
						n_core_mem_rsp[83-:64] = r_req2[230-:64];
					end
					else if (t_port2_hit_cache && (!r_hit_busy_addr2 & !r_pending_tlb_miss)) begin
						n_core_mem_rsp[147-:64] = t_rsp_data2[63:0];
						n_core_mem_rsp[7] = t_rsp_dst_valid2;
						n_cache_hits = r_cache_hits + 'd1;
						n_core_mem_rsp_valid = 1'b1;
						n_core_mem_rsp[1] = r_req2[153];
					end
					else begin
						t_push_miss = 1'b1;
						if (t_port2_hit_cache)
							n_cache_hits = r_cache_hits + 'd1;
					end
				end
				if (r_got_req) begin
					if ((r_valid_out && (r_tag_out == r_cache_tag)) && !r_req[145]) begin
						if (r_req[166])
							t_reset_graduated = 1'b1;
						else begin
							n_core_mem_rsp[147-:64] = t_rsp_data[63:0];
							n_core_mem_rsp[7] = t_rsp_dst_valid;
							n_core_mem_rsp_valid = 1'b1;
							n_core_mem_rsp[1] = r_req[153];
						end
					end
					else if (((r_valid_out && r_dirty_out) && (r_tag_out != r_cache_tag)) && !r_req[145]) begin
						t_got_miss = 1'b1;
						n_inhibit_write = 1'b1;
						if ((r_hit_busy_addr && r_is_retry) || !r_hit_busy_addr) begin
							n_mem_req_addr = {r_tag_out, r_cache_idx, 4'd0};
							n_mem_req_opcode = 4'd7;
							n_mem_req_store_data = t_data;
							n_inhibit_write = 1'b1;
							t_miss_idx = r_cache_idx;
							t_miss_addr = r_req[230-:64];
							n_lock_cache = 1'b1;
							if ((rr_cache_idx == r_cache_idx) && rr_last_wr) begin
								t_cache_idx = r_cache_idx;
								n_state = 4'd4;
								n_mem_req_valid = 1'b0;
							end
							else begin
								n_state = 4'd3;
								n_mem_req_valid = 1'b1;
							end
						end
					end
					else begin
						t_got_miss = 1'b1;
						n_inhibit_write = 1'b0;
						if (r_req[145]) begin
							n_state = (r_req[166] ? 4'd14 : 4'd13);
							n_mem_req_store_data = {64'd0, r_req[131-:64]};
							n_mem_req_addr = r_req[230-:64];
							n_mem_req_opcode = r_req[162-:4];
							n_mem_req_uc = 1'b1;
							n_mem_req_valid = 1'b1;
						end
						else if (((r_hit_busy_addr && r_is_retry) || !r_hit_busy_addr) || r_lock_cache) begin
							t_miss_idx = r_cache_idx;
							t_miss_addr = r_req[230-:64];
							t_cache_idx = r_cache_idx;
							if ((rr_cache_idx == r_cache_idx) && rr_last_wr) begin
								n_mem_req_addr = {r_tag_out, r_cache_idx, 4'd0};
								n_lock_cache = 1'b1;
								n_mem_req_opcode = 4'd7;
								n_state = 4'd4;
								n_mem_req_valid = 1'b0;
							end
							else begin
								n_lock_cache = 1'b0;
								n_mem_req_addr = {r_req[230:171], 4'd0};
								n_mem_req_opcode = 4'd4;
								n_state = 4'd3;
								n_mem_req_valid = 1'b1;
							end
						end
						else
							$stop;
					end
				end
				else if (n_pending_tlb_miss) begin
					n_state = 4'd11;
					n_page_walk_gnt = 1'b0;
					n_page_walk_req_valid = 1'b1;
				end
				if (((!mem_q_empty && !t_got_miss) && !r_lock_cache) && !n_pending_tlb_miss) begin
					if (!t_mh_block) begin
						if (t_mem_head[166] || t_mem_head[164]) begin
							if (w_st_amo_grad && (core_store_data_valid ? t_mem_head[144-:5] == core_store_data[4-:5] : 1'b0)) begin
								t_pop_mq = 1'b1;
								core_store_data_ack = 1'b1;
								n_req = t_mem_head;
								n_req[131-:64] = core_store_data[68-:64];
								t_cache_idx = t_mem_head[178:171];
								t_cache_tag = t_mem_head[230:179];
								t_addr = t_mem_head[230-:64];
								t_got_req = 1'b1;
								n_is_retry = 1'b1;
								n_last_wr = 1'b1;
							end
							else if (drain_ds_complete && dead_rob_mask[t_mem_head[144-:5]]) begin
								t_pop_mq = 1'b1;
								t_force_clear_busy = 1'b1;
							end
						end
						else begin
							t_pop_mq = 1'b1;
							n_req = t_mem_head;
							t_cache_idx = t_mem_head[178:171];
							t_cache_tag = t_mem_head[230:179];
							t_addr = t_mem_head[230-:64];
							t_got_req = 1'b1;
							n_is_retry = 1'b1;
							n_last_rd = 1'b1;
							t_got_rd_retry = 1'b1;
						end
					end
				end
				if (((((((core_mem_va_req_valid && !t_got_miss) && !(mem_q_almost_full || mem_q_full)) && !t_got_rd_retry) && !((r_last_wr2 && (r_cache_idx2 == core_mem_va_req[178:171])) && !core_mem_va_req[166])) && !(n_pending_tlb_miss | r_pending_tlb_miss)) && !t_cm_block_stall) && !r_rob_inflight[core_mem_va_req[144-:5]]) begin
					t_cache_idx2 = core_mem_va_req[178:171];
					t_cache_tag2 = core_mem_va_req[230:179];
					n_req2 = core_mem_va_req;
					core_mem_va_req_ack = 1'b1;
					t_got_req2 = 1'b1;
					t_tlb_xlat = 1'b1;
					n_tlb_addr = core_mem_va_req[230-:64];
					n_last_wr2 = core_mem_va_req[166];
					n_last_rd2 = !core_mem_va_req[166];
					n_cache_accesses = r_cache_accesses + 'd1;
				end
				else if ((r_flush_req && mem_q_empty) && !(r_got_req && r_last_wr)) begin
					if (n_state != r_state)
						$stop;
					n_state = 4'd5;
					if (!mem_q_empty)
						$stop;
					if (r_got_req && r_last_wr)
						$stop;
					t_cache_idx = 'd0;
					n_flush_req = 1'b0;
				end
				else if (((r_flush_cl_req && mem_q_empty) && !(r_got_req && r_last_wr)) && !(((n_page_walk_req_valid | t_got_miss) | r_wr_array) | t_wr_array)) begin
					if (n_state != r_state)
						$stop;
					if (!mem_q_empty)
						$stop;
					if (r_got_req && r_last_wr)
						$stop;
					t_cache_idx = l2_probe_addr[11:IDX_START];
					n_flush_cl_req = 1'b0;
					n_flush_was_active = 1'b1;
					n_state = 4'd8;
				end
			end
			4'd4: begin
				n_mem_req_valid = 1'b1;
				n_state = 4'd3;
				n_mem_req_store_data = t_data;
			end
			4'd3:
				if (mem_rsp_valid) begin
					n_state = 4'd10;
					n_inhibit_write = 1'b0;
					if (!((r_req[166] || r_req[164]) || r_lock_cache)) begin
						t_ack_ld_early = 1'b1;
						n_core_mem_rsp[19-:5] = r_req[144-:5];
						n_core_mem_rsp[14-:7] = r_req[139-:7];
						n_core_mem_rsp[147-:64] = t_rsp_data[63:0];
						n_core_mem_rsp[1] = r_req[153];
						n_core_mem_rsp_valid = 1'b1;
						n_core_mem_rsp[7] = r_req[132] & n_core_mem_rsp_valid;
					end
				end
			4'd10: begin
				t_cache_idx = r_req[178:171];
				t_cache_tag = r_req[230:179];
				n_last_wr = r_req[166];
				t_got_req = r_req[166] | (r_ack_ld_early == 1'b0);
				t_addr = r_req[230-:64];
				n_did_reload = 1'b1;
				n_state = 4'd2;
			end
			4'd8:
				if (r_dirty_out & w_flush_hit) begin
					n_mem_req_addr = {r_tag_out, r_cache_idx, 4'd0};
					n_mem_req_opcode = 4'd7;
					n_mem_req_store_data = t_data;
					n_state = 4'd9;
					n_inhibit_write = 1'b1;
					n_mem_req_valid = 1'b1;
				end
				else begin
					n_state = (r_flush_was_active ? 4'd2 : 4'd11);
					n_flush_was_active = 1'b0;
					t_mark_invalid = w_flush_hit;
					n_l2_probe_ack = 1'b1;
				end
			4'd9:
				if (mem_rsp_valid) begin
					n_state = (n_flush_was_active ? 4'd2 : 4'd11);
					n_flush_was_active = 1'b0;
					n_inhibit_write = 1'b0;
					n_l2_probe_ack = 1'b1;
				end
			4'd5: begin
				t_cache_idx = r_cache_idx + 'd1;
				if (!r_dirty_out) begin
					t_mark_invalid = 1'b1;
					t_cache_idx = r_cache_idx + 'd1;
					if (r_cache_idx == 255) begin
						n_state = 4'd2;
						n_flush_complete = 1'b1;
					end
				end
				else begin
					n_mem_req_addr = {r_tag_out, r_cache_idx, 4'd0};
					n_mem_req_opcode = 4'd7;
					n_mem_req_store_data = t_data;
					n_state = (r_cache_idx == 255 ? 4'd7 : 4'd6);
					n_inhibit_write = 1'b1;
					n_mem_req_valid = 1'b1;
				end
			end
			4'd7: begin
				t_cache_idx = r_cache_idx;
				if (mem_rsp_valid) begin
					n_state = 4'd2;
					n_inhibit_write = 1'b0;
					n_flush_complete = 1'b1;
				end
			end
			4'd6: begin
				t_cache_idx = r_cache_idx;
				if (mem_rsp_valid) begin
					n_state = 4'd5;
					n_inhibit_write = 1'b0;
				end
			end
			4'd11:
				if (page_walk_rsp_valid) begin
					t_reload_tlb = page_walk_rsp[71] == 1'b0;
					n_state = 4'd12;
					if (page_walk_rsp[71]) begin
						n_req2[162-:4] = 4'd10;
						n_req2[166] = 1'b0;
						n_req2[151] = 1'b1;
						n_req2[150-:5] = (r_req2[166] | r_req2[164] ? 5'd15 : 5'd13);
					end
				end
				else if (n_flush_cl_req) begin
					n_state = 4'd8;
					n_flush_cl_req = 1'b0;
					t_cache_idx = l2_probe_addr[11:IDX_START];
					n_flush_was_active = 1'b0;
				end
			4'd12: begin
				n_page_walk_gnt = 1'b0;
				n_state = 4'd2;
				t_replay_req2 = 1'b1;
				t_tlb_xlat = 1'b1;
			end
			4'd13:
				if (mem_rsp_valid) begin
					t_ack_ld_early = 1'b1;
					n_core_mem_rsp[19-:5] = r_req[144-:5];
					n_core_mem_rsp[14-:7] = r_req[139-:7];
					n_core_mem_rsp[147-:64] = t_rsp_data[63:0];
					n_core_mem_rsp[1] = r_req[153];
					n_core_mem_rsp_valid = 1'b1;
					n_core_mem_rsp[7] = r_req[132] & n_core_mem_rsp_valid;
					n_state = 4'd15;
				end
			4'd14:
				if (mem_rsp_valid) begin
					n_state = 4'd15;
					t_ack_ld_early = 1'b1;
				end
			4'd15: n_state = 4'd2;
			default:
				;
		endcase
	end
	always @(negedge clk) begin
		if ((((r_state == 4'd13) || (r_state == 4'd14)) && mem_rsp_valid) && t_write_dirty_en)
			$stop;
		if (t_push_miss && mem_q_full) begin
			$display("attempting to push to a full memory queue");
			$stop;
		end
		if (t_pop_mq && mem_q_empty) begin
			$display("attempting to pop an empty memory queue");
			$stop;
		end
	end
	initial _sv2v_0 = 0;
endmodule

module addsub (
	A,
	B,
	is_sub,
	Y
);
	parameter W = 32;
	input [W - 1:0] A;
	input [W - 1:0] B;
	input is_sub;
	output wire [W - 1:0] Y;
	wire [W - 1:0] w_s;
	wire [W - 1:0] w_c;
	wire [W - 1:0] w_zero = {W {1'b0}};
	wire [W - 1:0] w_one = {{W - 1 {1'b0}}, 1'b1};
	csa #(.N(W)) csa0(
		.a(A),
		.b((is_sub ? ~B : B)),
		.cin((is_sub ? w_one : w_zero)),
		.s(w_s),
		.cout(w_c)
	);
	wire [W - 1:0] w_srcA = {w_c[W - 2:0], 1'b0};
	wire [W - 1:0] w_srcB = w_s;
	assign Y = w_srcA + w_srcB;
endmodule



module popcount (
	in,
	out
);
	reg _sv2v_0;
	parameter LG_N = 2;
	localparam N = 1 << LG_N;
	localparam N2 = 1 << (LG_N - 1);
	input wire [N - 1:0] in;
	output reg [LG_N:0] out;
	generate
		if (LG_N == 2) begin : genblk1
			always @(*) begin
				if (_sv2v_0)
					;
				out = 'd0;
				case (in)
					4'b0000: out = 'd0;
					4'b0001: out = 'd1;
					4'b0010: out = 'd1;
					4'b0011: out = 'd2;
					4'b0100: out = 'd1;
					4'b0101: out = 'd2;
					4'b0110: out = 'd2;
					4'b0111: out = 'd3;
					4'b1000: out = 'd1;
					4'b1001: out = 'd2;
					4'b1010: out = 'd2;
					4'b1011: out = 'd3;
					4'b1100: out = 'd2;
					4'b1101: out = 'd3;
					4'b1110: out = 'd3;
					4'b1111: out = 'd4;
				endcase
			end
		end
		else begin : genblk1
			wire [LG_N - 1:0] t0;
			wire [LG_N - 1:0] t1;
			popcount #(.LG_N(LG_N - 1)) u0(
				.in(in[N2 - 1:0]),
				.out(t0)
			);
			popcount #(.LG_N(LG_N - 1)) u1(
				.in(in[N - 1:N2]),
				.out(t1)
			);
			wire [(LG_N >= 0 ? LG_N + 1 : 1 - LG_N):1] sv2v_tmp_53C6C;
			assign sv2v_tmp_53C6C = {1'b0, t0} + {1'b0, t1};
			always @(*) out = sv2v_tmp_53C6C;
		end
	endgenerate
	initial _sv2v_0 = 0;
endmodule

module ram1r1w (
	clk,
	rd_addr,
	wr_addr,
	wr_data,
	wr_en,
	rd_data
);
	input wire clk;
	parameter WIDTH = 1;
	parameter LG_DEPTH = 1;
	input wire [LG_DEPTH - 1:0] rd_addr;
	input wire [LG_DEPTH - 1:0] wr_addr;
	input wire [WIDTH - 1:0] wr_data;
	input wire wr_en;
	output reg [WIDTH - 1:0] rd_data;
	localparam DEPTH = 1 << LG_DEPTH;
	reg [WIDTH - 1:0] r_ram [DEPTH - 1:0];
	always @(posedge clk) begin
		rd_data <= r_ram[rd_addr];
		if (wr_en)
			r_ram[wr_addr] <= wr_data;
	end
endmodule
module ram1r1w_l1d_data (
	clk,
	rd_addr,
	wr_addr,
	wr_data,
	wr_en,
	wr_byte_en,
	rd_data
);
	input wire clk;
	parameter LG_DEPTH = 1;
	localparam WIDTH = 128;
	localparam NUM_BYTES = 16;
	input wire [LG_DEPTH - 1:0] rd_addr;
	input wire [LG_DEPTH - 1:0] wr_addr;
	input wire [127:0] wr_data;
	input wire wr_en;
	input wire [15:0] wr_byte_en;
	output reg [127:0] rd_data;
	localparam DEPTH = 1 << LG_DEPTH;
	reg [127:0] r_ram [DEPTH - 1:0];
	always @(posedge clk) begin
		rd_data <= r_ram[rd_addr];
		if (wr_en) begin
			if (wr_byte_en[0])
				r_ram[wr_addr][0+:8] <= wr_data[7:0];
			if (wr_byte_en[1])
				r_ram[wr_addr][8+:8] <= wr_data[15:8];
			if (wr_byte_en[2])
				r_ram[wr_addr][16+:8] <= wr_data[23:16];
			if (wr_byte_en[3])
				r_ram[wr_addr][24+:8] <= wr_data[31:24];
			if (wr_byte_en[4])
				r_ram[wr_addr][32+:8] <= wr_data[39:32];
			if (wr_byte_en[5])
				r_ram[wr_addr][40+:8] <= wr_data[47:40];
			if (wr_byte_en[6])
				r_ram[wr_addr][48+:8] <= wr_data[55:48];
			if (wr_byte_en[7])
				r_ram[wr_addr][56+:8] <= wr_data[63:56];
			if (wr_byte_en[8])
				r_ram[wr_addr][64+:8] <= wr_data[71:64];
			if (wr_byte_en[9])
				r_ram[wr_addr][72+:8] <= wr_data[79:72];
			if (wr_byte_en[10])
				r_ram[wr_addr][80+:8] <= wr_data[87:80];
			if (wr_byte_en[11])
				r_ram[wr_addr][88+:8] <= wr_data[95:88];
			if (wr_byte_en[12])
				r_ram[wr_addr][96+:8] <= wr_data[103:96];
			if (wr_byte_en[13])
				r_ram[wr_addr][104+:8] <= wr_data[111:104];
			if (wr_byte_en[14])
				r_ram[wr_addr][112+:8] <= wr_data[119:112];
			if (wr_byte_en[15])
				r_ram[wr_addr][120+:8] <= wr_data[127:120];
		end
	end
endmodule

module mul (
	clk,
	reset,
	is_signed,
	is_high,
	go,
	is_mulw,
	src_A,
	src_B,
	rob_ptr_in,
	prf_ptr_in,
	y,
	complete,
	rob_ptr_out,
	prf_ptr_val_out,
	prf_ptr_out
);
	reg _sv2v_0;
	input wire clk;
	input wire reset;
	input wire is_signed;
	input wire is_high;
	input wire go;
	input wire is_mulw;
	input wire [63:0] src_A;
	input wire [63:0] src_B;
	input wire [4:0] rob_ptr_in;
	input wire [6:0] prf_ptr_in;
	output reg [63:0] y;
	output wire complete;
	output wire [4:0] rob_ptr_out;
	output wire prf_ptr_val_out;
	output wire [6:0] prf_ptr_out;
	reg [3:0] r_is_high;
	reg [3:0] r_is_mulw;
	reg [3:0] r_complete;
	reg [3:0] r_gpr_val;
	reg [6:0] r_gpr_ptr [3:0];
	reg [4:0] r_rob_ptr [3:0];
	assign complete = r_complete[3];
	assign rob_ptr_out = r_rob_ptr[3];
	assign prf_ptr_val_out = r_gpr_val[3];
	assign prf_ptr_out = r_gpr_ptr[3];
	reg [127:0] t_mul;
	reg [127:0] r_mul [3:0];
	wire [127:0] w_sext_A = {{64 {src_A[63]}}, src_A};
	wire [127:0] w_sext_B = {{64 {src_B[63]}}, src_B};
	wire [63:0] w_mulw = {{32 {r_mul[3][31]}}, r_mul[3][31:0]};
	always @(*) begin
		if (_sv2v_0)
			;
		t_mul = (is_signed ? $signed(w_sext_A) * $signed(w_sext_B) : src_A * src_B);
		if (r_is_high[3])
			y = r_mul[3][127:64];
		else
			y = (r_is_mulw[3] ? w_mulw : r_mul[3][63:0]);
	end
	always @(posedge clk) begin
		r_mul[0] <= t_mul;
		begin : sv2v_autoblock_1
			integer i;
			for (i = 1; i <= 3; i = i + 1)
				r_mul[i] <= r_mul[i - 1];
		end
	end
	always @(posedge clk)
		if (reset) begin
			begin : sv2v_autoblock_2
				integer i;
				for (i = 0; i <= 3; i = i + 1)
					begin
						r_rob_ptr[i] <= 'd0;
						r_gpr_ptr[i] <= 'd0;
					end
			end
			r_complete <= 'd0;
			r_gpr_val <= 'd0;
			r_is_high <= 'd0;
			r_is_mulw <= 'd0;
		end
		else begin : sv2v_autoblock_3
			integer i;
			for (i = 0; i <= 3; i = i + 1)
				if (i == 0) begin
					r_complete[0] <= go;
					r_is_high[0] <= is_high;
					r_rob_ptr[0] <= rob_ptr_in;
					r_gpr_val[0] <= go;
					r_gpr_ptr[0] <= prf_ptr_in;
					r_is_mulw[0] <= is_mulw;
				end
				else begin
					r_complete[i] <= r_complete[i - 1];
					r_is_high[i] <= r_is_high[i - 1];
					r_rob_ptr[i] <= r_rob_ptr[i - 1];
					r_gpr_val[i] <= r_gpr_val[i - 1];
					r_gpr_ptr[i] <= r_gpr_ptr[i - 1];
					r_is_mulw[i] <= r_is_mulw[i - 1];
				end
		end
	initial _sv2v_0 = 0;
endmodule

module count_leading_zeros (
	in,
	y
);
	reg _sv2v_0;
	parameter LG_N = 2;
	localparam N = 1 << LG_N;
	localparam N2 = 1 << (LG_N - 1);
	input wire [N - 1:0] in;
	output reg [LG_N:0] y;
	wire [LG_N - 1:0] t0;
	wire [LG_N - 1:0] t1;
	wire lo_z = in[N2 - 1:0] == 'd0;
	wire hi_z = in[N - 1:N2] == 'd0;
	generate
		if (LG_N == 2) begin : genblk1
			always @(*) begin
				if (_sv2v_0)
					;
				y = 'd0;
				casez (in)
					4'b0000: y = 3'd4;
					4'b0001: y = 3'd3;
					4'b001z: y = 3'd2;
					4'b01zz: y = 3'd1;
					4'b1zzz: y = 3'd0;
					default: y = 3'd0;
				endcase
			end
		end
		else begin : genblk1
			count_leading_zeros #(.LG_N(LG_N - 1)) f0(
				.in(in[N2 - 1:0]),
				.y(t0)
			);
			count_leading_zeros #(.LG_N(LG_N - 1)) f1(
				.in(in[N - 1:N2]),
				.y(t1)
			);
			always @(*) begin
				if (_sv2v_0)
					;
				y = N;
				if (hi_z)
					y = N2 + t0;
				else
					y = {1'b0, t1};
			end
		end
	endgenerate
	initial _sv2v_0 = 0;
endmodule

module core (
	clk,
	reset,
	putchar_fifo_out,
	putchar_fifo_empty,
	putchar_fifo_pop,
	putchar_fifo_wptr,
	putchar_fifo_rptr,
	core_state,
	restart_complete,
	syscall_emu,
	took_exc,
	priv,
	clear_tlb,
	paging_active,
	page_table_root,
	mode64,
	head_of_rob_ptr_valid,
	head_of_rob_ptr,
	resume,
	memq_empty,
	l2_empty,
	drain_ds_complete,
	dead_rob_mask,
	resume_pc,
	ready_for_resume,
	flush_req_l1d,
	flush_req_l1i,
	flush_cl_req,
	flush_cl_addr,
	l1d_flush_complete,
	l1i_flush_complete,
	l2_flush_complete,
	insn,
	insn_valid,
	insn_ack,
	insn_two,
	insn_valid_two,
	insn_ack_two,
	branch_pc,
	target_pc,
	branch_pc_valid,
	branch_pc_is_indirect,
	branch_fault,
	took_branch,
	branch_pht_idx,
	restart_pc,
	restart_src_pc,
	restart_src_is_indirect,
	restart_valid,
	restart_ack,
	core_mem_req_ack,
	core_mem_req,
	core_mem_req_valid,
	core_store_data_valid,
	core_store_data,
	core_store_data_ack,
	core_mem_rsp,
	core_mem_rsp_valid,
	alloc_valid,
	alloc_two_valid,
	iq_none_valid,
	iq_one_valid,
	in_branch_recovery,
	retire_reg_ptr,
	retire_reg_data,
	retire_reg_valid,
	retire_reg_two_ptr,
	retire_reg_two_data,
	retire_reg_two_valid,
	retire_valid,
	retire_two_valid,
	retire_pc,
	retire_two_pc,
	rob_empty,
	retired_call,
	retired_ret,
	retired_rob_ptr_valid,
	retired_rob_ptr_two_valid,
	retired_rob_ptr,
	retired_rob_ptr_two,
	monitor_ack,
	mtimecmp,
	mtimecmp_val,
	took_irq,
	got_break,
	got_ud,
	got_bad_addr,
	got_monitor,
	inflight,
	epc,
	core_mark_dirty_valid,
	core_mark_dirty_addr,
	core_mark_dirty_rsp_valid,
	counters
);
	reg _sv2v_0;
	input wire clk;
	input wire reset;
	output wire [7:0] putchar_fifo_out;
	output wire putchar_fifo_empty;
	input wire putchar_fifo_pop;
	output wire [3:0] putchar_fifo_wptr;
	output wire [3:0] putchar_fifo_rptr;
	output wire [4:0] core_state;
	output wire restart_complete;
	input wire syscall_emu;
	output wire took_exc;
	output wire [1:0] priv;
	output wire clear_tlb;
	output wire paging_active;
	output wire [63:0] page_table_root;
	output wire mode64;
	output wire head_of_rob_ptr_valid;
	output wire [4:0] head_of_rob_ptr;
	input wire resume;
	input wire memq_empty;
	input wire l2_empty;
	output reg drain_ds_complete;
	output wire [31:0] dead_rob_mask;
	input wire [63:0] resume_pc;
	output wire ready_for_resume;
	output wire flush_req_l1d;
	output wire flush_req_l1i;
	output wire flush_cl_req;
	output wire [63:0] flush_cl_addr;
	input wire l1d_flush_complete;
	input wire l1i_flush_complete;
	input wire l2_flush_complete;
	input wire [177:0] insn;
	input wire insn_valid;
	output wire insn_ack;
	input wire [177:0] insn_two;
	input wire insn_valid_two;
	output wire insn_ack_two;
	output wire [63:0] restart_pc;
	output wire [63:0] restart_src_pc;
	output wire restart_src_is_indirect;
	output wire restart_valid;
	input wire restart_ack;
	output wire [63:0] branch_pc;
	output wire [63:0] target_pc;
	output wire branch_pc_valid;
	output wire branch_pc_is_indirect;
	output wire branch_fault;
	output wire took_branch;
	output wire [15:0] branch_pht_idx;
	input wire core_mem_req_ack;
	output reg core_mem_req_valid;
	output reg [230:0] core_mem_req;
	output wire core_store_data_valid;
	output wire [68:0] core_store_data;
	input wire core_store_data_ack;
	input wire [147:0] core_mem_rsp;
	input wire core_mem_rsp_valid;
	output reg [4:0] retire_reg_ptr;
	output reg [63:0] retire_reg_data;
	output reg retire_reg_valid;
	output reg [4:0] retire_reg_two_ptr;
	output reg [63:0] retire_reg_two_data;
	output reg retire_reg_two_valid;
	output reg alloc_valid;
	output reg alloc_two_valid;
	output reg iq_one_valid;
	output reg iq_none_valid;
	output wire in_branch_recovery;
	output reg retire_valid;
	output reg retire_two_valid;
	output reg [63:0] retire_pc;
	output reg [63:0] retire_two_pc;
	output reg retired_call;
	output reg retired_ret;
	output reg retired_rob_ptr_valid;
	output reg retired_rob_ptr_two_valid;
	output reg [4:0] retired_rob_ptr;
	output reg [4:0] retired_rob_ptr_two;
	input wire monitor_ack;
	output reg rob_empty;
	input wire [63:0] mtimecmp;
	input wire mtimecmp_val;
	output wire took_irq;
	output wire got_break;
	output wire got_ud;
	output wire got_bad_addr;
	output wire got_monitor;
	output wire [5:0] inflight;
	output wire [63:0] epc;
	output wire core_mark_dirty_valid;
	output wire [63:0] core_mark_dirty_addr;
	input wire core_mark_dirty_rsp_valid;
	input wire [639:0] counters;
	localparam N_PRF_ENTRIES = 128;
	localparam N_ROB_ENTRIES = 32;
	localparam N_UQ_ENTRIES = 16;
	localparam N_DQ_ENTRIES = 4;
	localparam HI_EBITS = 32;
	reg t_push_dq_one;
	reg t_push_dq_two;
	reg [251:0] r_dq [3:0];
	reg [2:0] r_dq_head_ptr;
	reg [2:0] n_dq_head_ptr;
	reg [2:0] r_dq_next_head_ptr;
	reg [2:0] n_dq_next_head_ptr;
	reg [2:0] r_dq_next_tail_ptr;
	reg [2:0] n_dq_next_tail_ptr;
	reg [2:0] r_dq_cnt;
	reg [2:0] n_dq_cnt;
	reg [2:0] r_dq_tail_ptr;
	reg [2:0] n_dq_tail_ptr;
	reg t_dq_empty;
	reg t_dq_full;
	reg t_dq_next_empty;
	reg t_dq_next_full;
	reg r_got_restart_ack;
	reg n_got_restart_ack;
	wire [63:0] w_exc_pc;
	wire w_exec_clear_tlb;
	reg [241:0] r_rob [31:0];
	reg [63:0] r_rob_addr [31:0];
	reg [31:0] r_rob_complete;
	reg [31:0] r_rob_sd_complete;
	wire t_core_store_data_ptr_valid;
	wire [4:0] t_core_store_data_ptr;
	reg t_rob_head_complete;
	reg t_rob_next_head_complete;
	reg [31:0] r_rob_inflight;
	reg [31:0] r_rob_dead_insns;
	reg [31:0] t_clr_mask;
	reg [241:0] t_rob_head;
	reg [241:0] t_rob_next_head;
	reg [241:0] t_rob_tail;
	reg [241:0] t_rob_next_tail;
	reg [127:0] n_prf_free;
	reg [127:0] r_prf_free;
	wire [127:0] w_prf_free_even;
	wire [127:0] w_prf_free_odd;
	wire w_prf_free_even_full;
	wire w_prf_free_odd_full;
	reg r_bank_sel;
	reg [127:0] n_retire_prf_free;
	reg [127:0] r_retire_prf_free;
	reg [6:0] n_prf_entry;
	reg [6:0] n_prf_entry2;
	reg [5:0] r_rob_head_ptr;
	reg [5:0] n_rob_head_ptr;
	reg [5:0] r_rob_next_head_ptr;
	reg [5:0] n_rob_next_head_ptr;
	reg [5:0] r_rob_tail_ptr;
	reg [5:0] n_rob_tail_ptr;
	reg [5:0] r_rob_next_tail_ptr;
	reg [5:0] n_rob_next_tail_ptr;
	reg t_rob_empty;
	reg t_rob_full;
	reg t_rob_next_full;
	reg t_rob_next_empty;
	reg [223:0] r_alloc_rat;
	reg [223:0] r_retire_rat;
	wire [31:0] uq_wait;
	wire [31:0] mq_wait;
	reg t_alloc;
	reg t_alloc_two;
	reg t_retire;
	reg t_retire_two;
	reg t_rat_copy;
	reg t_clr_rob;
	reg t_took_irq;
	reg r_took_irq;
	reg t_possible_to_alloc;
	reg t_fold_uop;
	reg t_fold_uop2;
	reg t_clr_dq;
	reg t_enough_iprfs;
	reg t_enough_next_iprfs;
	reg t_bump_rob_head;
	reg [63:0] n_restart_pc;
	reg [63:0] r_restart_pc;
	reg [63:0] n_restart_src_pc;
	reg [63:0] r_restart_src_pc;
	reg n_restart_src_is_indirect;
	reg r_restart_src_is_indirect;
	reg [63:0] n_branch_pc;
	reg [63:0] r_branch_pc;
	reg [63:0] n_target_pc;
	reg [63:0] r_target_pc;
	reg n_took_branch;
	reg r_took_branch;
	reg n_branch_valid;
	reg r_branch_valid;
	reg n_branch_pc_is_indirect;
	reg r_branch_pc_is_indirect;
	reg n_branch_fault;
	reg r_branch_fault;
	reg [15:0] n_branch_pht_idx;
	reg [15:0] r_branch_pht_idx;
	reg n_restart_valid;
	reg r_restart_valid;
	reg n_take_br;
	reg r_take_br;
	reg n_got_break;
	reg r_got_break;
	reg n_pending_break;
	reg r_pending_break;
	reg n_pending_badva;
	reg r_pending_badva;
	reg n_pending_ii;
	reg r_pending_ii;
	reg n_got_ud;
	reg r_got_ud;
	reg n_got_monitor;
	reg r_got_monitor;
	reg n_got_bad_addr;
	reg r_got_bad_addr;
	reg n_l1i_flush_complete;
	reg r_l1i_flush_complete;
	reg n_l1d_flush_complete;
	reg r_l1d_flush_complete;
	reg n_l2_flush_complete;
	reg r_l2_flush_complete;
	reg [4:0] n_cause;
	reg [4:0] r_cause;
	reg [63:0] r_tval;
	reg [63:0] n_tval;
	reg [63:0] r_epc;
	reg [63:0] n_epc;
	wire [141:0] t_complete_bundle_1;
	wire [141:0] t_complete_bundle_2;
	wire t_complete_valid_1;
	wire t_complete_valid_2;
	reg t_any_complete;
	reg t_free_reg;
	reg [6:0] t_free_reg_ptr;
	reg t_free_reg_two;
	reg [6:0] t_free_reg_two_ptr;
	reg [7:0] t_gpr_ffs;
	reg [7:0] t_gpr_ffs2;
	reg t_gpr_ffs_full;
	reg t_gpr_ffs2_full;
	wire [7:0] w_gpr_ffs_even;
	wire [7:0] w_gpr_ffs_odd;
	wire t_uq_full;
	wire t_uq_next_full;
	reg n_ready_for_resume;
	reg r_ready_for_resume;
	wire [230:0] t_mem_req;
	wire t_mem_req_valid;
	reg n_machine_clr;
	reg r_machine_clr;
	reg n_flush_req_l1d;
	reg r_flush_req_l1d;
	reg n_flush_req_l1i;
	reg r_flush_req_l1i;
	reg n_flush_cl_req;
	reg r_flush_cl_req;
	reg [63:0] n_flush_cl_addr;
	reg [63:0] r_flush_cl_addr;
	reg r_ds_done;
	reg n_ds_done;
	reg n_mmu_mark_dirty;
	reg r_mmu_mark_dirty;
	reg [63:0] r_dirty_addr;
	reg n_clear_tlb;
	reg r_clear_tlb;
	assign core_mark_dirty_valid = r_mmu_mark_dirty;
	assign core_mark_dirty_addr = r_dirty_addr;
	assign clear_tlb = w_exec_clear_tlb | r_clear_tlb;
	reg t_can_retire_rob_head;
	reg t_arch_fault;
	reg n_arch_fault;
	reg r_arch_fault;
	reg [4:0] r_state;
	reg [4:0] n_state;
	assign core_state = r_state;
	reg r_pending_fault;
	reg n_pending_fault;
	reg [31:0] r_restart_cycles;
	reg [31:0] n_restart_cycles;
	reg r_irq;
	reg n_irq;
	wire [1:0] w_priv;
	wire w_priv_update;
	assign priv = w_priv;
	wire [63:0] w_mip;
	wire [63:0] w_mie;
	wire [63:0] w_mideleg;
	wire [63:0] w_mstatus;
	wire [63:0] w_pending_irq = w_mip & w_mie;
	wire w_mstatus_mie = w_mstatus[3];
	wire w_mstatus_sie = w_mstatus[1];
	wire [63:0] w_en_m_irqs = (w_mstatus_mie ? ~w_mideleg : 64'd0);
	wire [63:0] w_en_s_irqs = ~w_mideleg | (w_mstatus_sie ? w_mideleg : 64'd0);
	wire [63:0] w_enabled_irqs = (w_priv == 2'd3 ? w_en_m_irqs : (w_priv == 2'd1 ? w_en_s_irqs : ~64'd0)) & w_pending_irq;
	wire w_any_irq = |w_enabled_irqs[31:0] & |w_pending_irq[31:0];
	wire [5:0] w_irq_id;
	find_first_set #(5) irq_ffs(
		.in(w_enabled_irqs[31:0]),
		.y(w_irq_id)
	);
	wire t_divide_ready;
	always @(*) begin
		if (_sv2v_0)
			;
		core_mem_req_valid = t_mem_req_valid;
		core_mem_req = t_mem_req;
	end
	assign ready_for_resume = r_ready_for_resume;
	assign in_branch_recovery = (r_state == 5'd3) || (r_state == 5'd4);
	assign head_of_rob_ptr_valid = r_state == 5'd2;
	assign head_of_rob_ptr = r_rob_head_ptr[4:0];
	wire [63:0] w_rob_head_addr = r_rob_addr[r_rob_head_ptr[4:0]];
	assign flush_req_l1d = r_flush_req_l1d;
	assign flush_req_l1i = r_flush_req_l1i;
	assign flush_cl_req = r_flush_cl_req;
	assign flush_cl_addr = r_flush_cl_addr;
	assign took_irq = r_took_irq;
	assign got_break = r_got_break;
	assign got_ud = r_got_ud;
	assign got_bad_addr = r_got_bad_addr;
	assign got_monitor = r_got_monitor;
	assign epc = r_epc;
	popcount #(5) inflight0(
		.in(r_rob_inflight),
		.out(inflight)
	);
	reg [251:0] t_uop;
	wire [251:0] t_dec_uop;
	reg [251:0] t_alloc_uop;
	reg [251:0] t_uop2;
	wire [251:0] t_dec_uop2;
	reg [251:0] t_alloc_uop2;
	assign insn_ack = (!t_dq_full && insn_valid) && (r_state == 5'd2);
	assign insn_ack_two = (((!t_dq_full && insn_valid) && !t_dq_next_full) && insn_valid_two) && (r_state == 5'd2);
	assign restart_pc = r_restart_pc;
	assign restart_src_pc = r_restart_src_pc;
	assign restart_src_is_indirect = r_restart_src_is_indirect;
	assign dead_rob_mask = r_rob_dead_insns;
	assign restart_valid = r_restart_valid;
	assign branch_pc = r_branch_pc;
	assign target_pc = r_target_pc;
	assign branch_pc_valid = r_branch_valid;
	assign branch_pc_is_indirect = r_branch_pc_is_indirect;
	assign branch_fault = r_branch_fault;
	assign branch_pht_idx = r_branch_pht_idx;
	assign took_branch = r_took_branch;
	reg r_update_csr_exc;
	reg n_update_csr_exc;
	reg r_mode64;
	reg n_mode64;
	assign mode64 = r_mode64;
	assign took_exc = r_update_csr_exc;
	reg [63:0] r_cycle;
	always @(posedge clk) r_cycle <= (reset ? 'd0 : r_cycle + 'd1);
	always @(posedge clk)
		if (n_mmu_mark_dirty)
			r_dirty_addr <= w_rob_head_addr;
	always @(posedge clk)
		if (reset) begin
			r_arch_fault <= 1'b0;
			r_update_csr_exc <= 1'b0;
			r_flush_req_l1i <= 1'b0;
			r_flush_req_l1d <= 1'b0;
			r_flush_cl_req <= 1'b0;
			r_flush_cl_addr <= 'd0;
			r_restart_pc <= 'd0;
			r_restart_src_pc <= 'd0;
			r_restart_src_is_indirect <= 1'b0;
			r_branch_pc <= 'd0;
			r_target_pc <= 'd0;
			r_took_branch <= 1'b0;
			r_branch_valid <= 1'b0;
			r_branch_pc_is_indirect <= 1'b0;
			r_branch_fault <= 1'b0;
			r_branch_pht_idx <= 'd0;
			r_restart_valid <= 1'b0;
			r_take_br <= 1'b0;
			r_got_break <= 1'b0;
			r_pending_break <= 1'b0;
			r_pending_badva <= 1'b0;
			r_pending_ii <= 1'b0;
			r_got_ud <= 1'b0;
			r_got_bad_addr <= 1'b0;
			r_got_monitor <= 1'b0;
			r_ready_for_resume <= 1'b0;
			r_l1i_flush_complete <= 1'b0;
			r_l1d_flush_complete <= 1'b0;
			r_l2_flush_complete <= 1'b0;
			r_epc <= 'd0;
			drain_ds_complete <= 1'b0;
			r_ds_done <= 1'b0;
			r_mmu_mark_dirty <= 1'b0;
			r_clear_tlb <= 1'b0;
		end
		else begin
			r_arch_fault <= n_arch_fault;
			r_update_csr_exc <= n_update_csr_exc;
			r_flush_req_l1d <= n_flush_req_l1d;
			r_flush_req_l1i <= n_flush_req_l1i;
			r_flush_cl_req <= n_flush_cl_req;
			r_flush_cl_addr <= n_flush_cl_addr;
			r_restart_pc <= n_restart_pc;
			r_restart_src_pc <= n_restart_src_pc;
			r_restart_src_is_indirect <= n_restart_src_is_indirect;
			r_branch_pc <= n_branch_pc;
			r_target_pc <= n_target_pc;
			r_took_branch <= n_took_branch;
			r_branch_valid <= n_branch_valid;
			r_branch_pc_is_indirect <= n_branch_pc_is_indirect;
			r_branch_fault <= n_branch_fault;
			r_branch_pht_idx <= n_branch_pht_idx;
			r_restart_valid <= n_restart_valid;
			r_take_br <= n_take_br;
			r_got_break <= n_got_break;
			r_pending_break <= n_pending_break;
			r_pending_badva <= n_pending_badva;
			r_pending_ii <= n_pending_ii;
			r_got_ud <= n_got_ud;
			r_got_bad_addr <= n_got_bad_addr;
			r_got_monitor <= n_got_monitor;
			r_ready_for_resume <= n_ready_for_resume;
			r_l1i_flush_complete <= n_l1i_flush_complete;
			r_l1d_flush_complete <= n_l1d_flush_complete;
			r_l2_flush_complete <= n_l2_flush_complete;
			r_epc <= n_epc;
			drain_ds_complete <= r_ds_done;
			r_ds_done <= n_ds_done;
			r_mmu_mark_dirty <= n_mmu_mark_dirty;
			r_clear_tlb <= n_clear_tlb;
		end
	always @(posedge clk)
		if (reset) begin
			r_mode64 <= 1'b1;
			r_state <= 5'd0;
			r_irq <= 1'b0;
			r_restart_cycles <= 'd0;
			r_machine_clr <= 1'b0;
			r_got_restart_ack <= 1'b0;
			r_cause <= 5'd0;
			r_tval <= 'd0;
			r_pending_fault <= 1'b0;
		end
		else begin
			r_mode64 <= n_mode64;
			r_state <= n_state;
			r_irq <= n_irq;
			r_restart_cycles <= n_restart_cycles;
			r_machine_clr <= n_machine_clr;
			r_got_restart_ack <= n_got_restart_ack;
			r_cause <= n_cause;
			r_tval <= n_tval;
			r_pending_fault <= n_pending_fault;
		end
	always @(posedge clk)
		if (reset)
			r_took_irq <= 1'b0;
		else if (t_retire)
			r_took_irq <= 1'b0;
		else if (t_took_irq)
			r_took_irq <= 1'b1;
	always @(posedge clk)
		if (reset) begin
			retire_reg_ptr <= 'd0;
			retire_reg_data <= 'd0;
			retire_reg_valid <= 1'b0;
			retire_reg_two_ptr <= 'd0;
			retire_reg_two_data <= 'd0;
			retire_reg_two_valid <= 1'b0;
			retire_valid <= 1'b0;
			retire_two_valid <= 1'b0;
			alloc_valid <= 1'b0;
			rob_empty <= 1'b0;
			alloc_two_valid <= 1'b0;
			iq_one_valid <= 1'b0;
			iq_none_valid <= 1'b0;
			retire_pc <= 'd0;
			retire_two_pc <= 'd0;
			retired_call <= 1'b0;
			retired_ret <= 1'b0;
			retired_rob_ptr_valid <= 1'b0;
			retired_rob_ptr_two_valid <= 1'b0;
			retired_rob_ptr <= 'd0;
			retired_rob_ptr_two <= 'd0;
		end
		else begin
			retire_reg_ptr <= t_rob_head[229-:5];
			retire_reg_data <= t_rob_head[79-:64];
			retire_reg_valid <= t_rob_head[230] & t_retire;
			retire_reg_two_ptr <= t_rob_next_head[229-:5];
			retire_reg_two_data <= t_rob_next_head[79-:64];
			retire_reg_two_valid <= t_rob_next_head[230] & t_retire_two;
			retire_valid <= t_retire;
			retire_two_valid <= t_retire_two;
			rob_empty <= t_rob_empty;
			alloc_valid <= t_alloc;
			alloc_two_valid <= t_alloc_two;
			iq_one_valid <= !t_dq_empty && t_dq_next_empty;
			iq_none_valid <= t_dq_empty;
			retire_pc <= t_rob_head[210-:64];
			retire_two_pc <= t_rob_next_head[210-:64];
			retired_ret <= t_rob_head[233] && t_retire;
			retired_call <= t_rob_head[232] && t_retire;
			retired_rob_ptr_valid <= t_retire;
			retired_rob_ptr_two_valid <= t_retire_two;
			retired_rob_ptr <= r_rob_head_ptr[4:0];
			retired_rob_ptr_two <= r_rob_next_head_ptr[4:0];
		end
	reg t_restart_complete;
	assign restart_complete = t_restart_complete;
	always @(*) begin
		if (_sv2v_0)
			;
		n_mode64 = r_mode64;
		t_restart_complete = 1'b0;
		n_cause = r_cause;
		n_epc = r_epc;
		n_tval = r_tval;
		n_machine_clr = r_machine_clr;
		t_alloc = 1'b0;
		t_alloc_two = 1'b0;
		t_possible_to_alloc = 1'b0;
		t_retire = 1'b0;
		t_retire_two = 1'b0;
		t_rat_copy = 1'b0;
		t_clr_rob = 1'b0;
		t_clr_dq = 1'b0;
		n_state = r_state;
		n_irq = r_irq;
		n_restart_cycles = r_restart_cycles + 'd1;
		n_restart_pc = r_restart_pc;
		n_restart_src_pc = r_restart_src_pc;
		n_restart_src_is_indirect = r_restart_src_is_indirect;
		n_restart_valid = 1'b0;
		n_take_br = r_take_br;
		t_bump_rob_head = 1'b0;
		n_pending_fault = r_pending_fault;
		n_pending_badva = r_pending_badva;
		n_pending_ii = r_pending_ii;
		t_enough_iprfs = !(t_uop[221] && t_gpr_ffs_full);
		t_enough_next_iprfs = !(t_uop2[221] && t_gpr_ffs2_full);
		t_fold_uop = ((((t_uop[251-:7] == 7'd73) || (t_uop[251-:7] == 7'd96)) || (t_uop[251-:7] == 7'd94)) || (t_uop[251-:7] == 7'd95)) || (t_uop[251-:7] == 7'd64);
		t_fold_uop2 = ((((t_uop2[251-:7] == 7'd73) || (t_uop2[251-:7] == 7'd96)) || (t_uop2[251-:7] == 7'd94)) || (t_uop2[251-:7] == 7'd95)) || (t_uop2[251-:7] == 7'd64);
		n_ds_done = r_ds_done;
		n_flush_req_l1d = 1'b0;
		n_flush_req_l1i = 1'b0;
		n_flush_cl_req = 1'b0;
		n_flush_cl_addr = r_flush_cl_addr;
		n_got_break = r_got_break;
		n_pending_break = r_pending_break;
		n_got_ud = r_got_ud;
		n_got_bad_addr = r_got_bad_addr;
		n_got_restart_ack = r_got_restart_ack;
		n_got_monitor = r_got_monitor;
		n_ready_for_resume = 1'b0;
		n_update_csr_exc = 1'b0;
		n_mmu_mark_dirty = 1'b0;
		n_clear_tlb = 1'b0;
		n_l1i_flush_complete = r_l1i_flush_complete || l1i_flush_complete;
		n_l1d_flush_complete = r_l1d_flush_complete || l1d_flush_complete;
		n_l2_flush_complete = r_l2_flush_complete || l2_flush_complete;
		t_took_irq = 1'b0;
		if (r_state == 5'd2)
			n_got_restart_ack = 1'b0;
		else if (!r_got_restart_ack & restart_ack)
			n_got_restart_ack = 1;
		t_can_retire_rob_head = t_rob_head_complete && !t_rob_empty;
		if (t_complete_valid_1 || t_complete_valid_2)
			n_pending_fault = (r_pending_fault | (t_complete_valid_1 ? t_complete_bundle_1[135] : 1'b0)) | (t_complete_valid_2 ? t_complete_bundle_2[135] : 1'b0);
		t_arch_fault = t_rob_head[241] & t_rob_head[240];
		n_arch_fault = r_arch_fault;
		(* full_case, parallel_case *)
		case (r_state)
			5'd2:
				if (t_can_retire_rob_head) begin
					if (t_rob_head[241]) begin
						if (t_arch_fault) begin
							n_arch_fault = 1'b1;
							n_state = 5'd14;
							n_cause = t_rob_head[239-:5];
							n_epc = t_rob_head[210-:64];
							n_tval = 'd0;
							n_irq = t_rob_head[231];
						end
						else begin
							n_state = 5'd3;
							n_restart_cycles = 'd1;
							n_restart_valid = 1'b1;
							t_bump_rob_head = 1'b1;
						end
						n_ds_done = 1'b1;
						n_machine_clr = 1'b1;
						n_restart_pc = t_rob_head[146-:64];
						n_restart_src_pc = t_rob_head[210-:64];
						n_restart_src_is_indirect = t_rob_head[81];
						n_take_br = t_rob_head[80];
					end
					else if (t_rob_head[234]) begin
						$display("retiring dirty page mark insn, pc %x, target %x, addr %x, entry %d", t_rob_head[210-:64], t_rob_head[146-:64], w_rob_head_addr, r_rob_head_ptr[4:0]);
						n_state = 5'd17;
						n_ds_done = 1'b1;
						n_restart_pc = t_rob_head[146-:64];
						n_mmu_mark_dirty = 1'b1;
					end
					else if ((t_dq_empty ? 1'b0 : t_uop[23] == 1'b0)) begin
						if (t_uop[23])
							$stop;
						t_possible_to_alloc = (!t_rob_full && !t_uq_full) && !t_dq_empty;
						t_alloc = (((!t_rob_full && !r_pending_fault) && !t_uq_full) && !t_dq_empty) && t_enough_iprfs;
						t_alloc_two = ((((t_alloc && !t_uop2[23]) && !t_dq_next_empty) && !t_rob_next_full) && !t_uq_next_full) && t_enough_next_iprfs;
					end
					t_retire = t_rob_head_complete & !t_arch_fault;
					t_retire_two = ((((((((!t_rob_next_empty && t_retire) && !t_rob_head[241]) && !t_rob_head[234]) && !t_rob_next_head[241]) && t_rob_head_complete) && t_rob_next_head_complete) && (t_rob_head[82] ? !t_rob_next_head[82] : 1'b1)) && !t_rob_next_head[233]) && !t_rob_next_head[232];
				end
				else if (!t_dq_empty) begin
					if (t_uop[23] & t_rob_empty) begin
						if ((t_uop[251-:7] == 7'd13) | (t_uop[251-:7] == 7'd93)) begin
							n_flush_req_l1i = 1'b1;
							n_flush_req_l1d = 1'b1;
							n_state = 5'd6;
						end
						else
							n_state = 5'd5;
					end
					else if (!t_uop[23]) begin
						t_possible_to_alloc = (!t_rob_full && !t_uq_full) && !t_dq_empty;
						t_alloc = ((!t_rob_full && !t_uq_full) && !t_dq_empty) && t_enough_iprfs;
						t_alloc_two = ((((t_alloc && !t_uop2[23]) && !t_dq_next_empty) && !t_rob_next_full) && !t_uq_next_full) && t_enough_next_iprfs;
					end
				end
			5'd3:
				if (((r_rob_inflight == 'd0) & memq_empty) & t_divide_ready)
					n_state = 5'd4;
			5'd4: begin
				t_rat_copy = 1'b1;
				t_clr_rob = 1'b1;
				t_clr_dq = 1'b1;
				n_machine_clr = 1'b0;
				if (n_got_restart_ack) begin
					n_state = 5'd2;
					n_ds_done = 1'b0;
					n_pending_fault = 1'b0;
					t_restart_complete = 1'b1;
					n_arch_fault = 1'b0;
				end
			end
			5'd5: begin
				t_alloc = (((!t_rob_full & !t_uq_full) & (r_prf_free != 'd0)) & memq_empty) & !t_dq_empty;
				if (t_alloc)
					n_state = 5'd11;
			end
			5'd11:
				if (t_rob_head_complete) begin
					n_restart_pc = t_rob_head[146-:64];
					n_restart_src_pc = t_rob_head[210-:64];
					n_restart_src_is_indirect = 1'b0;
					n_restart_valid = 1'b1;
					n_pending_fault = 1'b0;
					n_state = 5'd12;
				end
			5'd12: begin
				t_clr_dq = 1'b1;
				if (n_got_restart_ack)
					n_state = 5'd2;
			end
			5'd13: begin
				t_clr_dq = 1'b1;
				if (n_got_restart_ack) begin
					t_retire = 1'b1;
					n_state = 5'd2;
				end
			end
			5'd6:
				if ((n_l1i_flush_complete && n_l1d_flush_complete) && n_l2_flush_complete) begin
					n_got_monitor = t_uop[251-:7] == 7'd13;
					n_state = (t_uop[251-:7] == 7'd13 ? 5'd7 : 5'd5);
					n_l1i_flush_complete = 1'b0;
					n_l1d_flush_complete = 1'b0;
					n_l2_flush_complete = 1'b0;
				end
			5'd7:
				if (monitor_ack) begin
					n_got_monitor = 1'b0;
					n_state = 5'd8;
				end
			5'd8: begin
				t_alloc = ((!t_rob_full && !t_uq_full) && (r_prf_free != 'd0)) && !t_dq_empty;
				n_state = 5'd9;
			end
			5'd9:
				if (t_rob_head_complete) begin
					n_restart_pc = t_rob_head[210-:64] + 'd4;
					n_restart_src_pc = t_rob_head[210-:64];
					n_restart_src_is_indirect = 1'b0;
					n_restart_valid = 1'b1;
					n_pending_fault = 1'b0;
					n_state = 5'd13;
				end
			5'd0:
				if ((n_l1i_flush_complete && n_l1d_flush_complete) && n_l2_flush_complete) begin
					n_state = 5'd1;
					n_ds_done = 1'b0;
					n_got_break = r_pending_break;
					n_got_ud = r_pending_ii;
					n_got_bad_addr = r_pending_badva;
					n_pending_break = 1'b0;
					n_pending_badva = 1'b0;
					n_pending_ii = 1'b0;
					n_ready_for_resume = 1'b1;
					n_l1i_flush_complete = 1'b0;
					n_l1d_flush_complete = 1'b0;
					n_l2_flush_complete = 1'b0;
				end
			5'd1:
				if (resume) begin
					n_restart_pc = resume_pc;
					n_restart_src_pc = t_rob_head[210-:64];
					n_restart_src_is_indirect = 1'b0;
					n_restart_valid = 1'b1;
					n_state = 5'd10;
					n_got_break = 1'b0;
					n_got_ud = 1'b0;
					t_clr_dq = 1'b1;
				end
				else
					n_ready_for_resume = 1'b1;
			5'd10: begin
				n_pending_fault = 1'b0;
				if (n_got_restart_ack)
					n_state = 5'd2;
			end
			5'd14: begin
				case (t_rob_head[239-:5])
					5'd3: n_pending_break = 1'b1;
					5'd2: n_pending_ii = 1'b1;
					5'd12: n_tval = t_rob_head[210-:64];
					5'd13: n_tval = w_rob_head_addr;
					5'd15: n_tval = w_rob_head_addr;
					default:
						;
				endcase
				t_bump_rob_head = 1'b1;
				if (syscall_emu) begin
					n_flush_req_l1i = 1'b1;
					n_flush_req_l1d = 1'b1;
					n_state = 5'd0;
					n_pending_badva = t_rob_head[239-:5] == 5'd0;
					n_pending_ii = t_rob_head[239-:5] == 5'd2;
				end
				else
					n_state = 5'd15;
			end
			5'd15: begin
				n_update_csr_exc = 1'b1;
				if (w_exc_pc == r_epc)
					$display("stuck in exception loop, w_exc_pc = %x, page_table_root = %x, cause %d", w_exc_pc, page_table_root, r_cause);
				n_state = 5'd16;
			end
			5'd16:
				if (w_priv_update) begin
					n_restart_pc = w_exc_pc;
					n_restart_valid = 1'b1;
					if (n_got_restart_ack)
						$stop;
					t_took_irq = r_irq;
					n_irq = 1'b0;
					n_state = 5'd3;
				end
			5'd17:
				if (core_mark_dirty_rsp_valid) begin
					n_clear_tlb = 1'b1;
					n_restart_valid = 1'b1;
					n_state = 5'd3;
				end
			default:
				;
		endcase
	end
	always @(posedge clk)
		if (reset) begin
			r_rob_head_ptr <= 'd0;
			r_rob_tail_ptr <= 'd0;
			r_rob_next_head_ptr <= 'd1;
			r_rob_next_tail_ptr <= 'd1;
		end
		else begin
			r_rob_head_ptr <= n_rob_head_ptr;
			r_rob_tail_ptr <= n_rob_tail_ptr;
			r_rob_next_head_ptr <= n_rob_next_head_ptr;
			r_rob_next_tail_ptr <= n_rob_next_tail_ptr;
		end
	wire [6:0] w_rn_srcA_1 = r_alloc_rat[t_uop[242:238] * 7+:7];
	wire [6:0] w_rn_srcB_1 = r_alloc_rat[t_uop[234:230] * 7+:7];
	wire [6:0] w_rn_srcA_2_ = r_alloc_rat[t_uop2[242:238] * 7+:7];
	wire [6:0] w_rn_srcB_2_ = r_alloc_rat[t_uop2[234:230] * 7+:7];
	wire w_srcA_match = t_uop[221] & (t_uop2[242:238] == t_uop[226:222]);
	wire w_srcB_match = t_uop[221] & (t_uop2[234:230] == t_uop[226:222]);
	wire [6:0] w_rn_srcA_2 = (w_srcA_match ? n_prf_entry : w_rn_srcA_2_);
	wire [6:0] w_rn_srcB_2 = (w_srcB_match ? n_prf_entry : w_rn_srcB_2_);
	always @(posedge clk)
		if (reset) begin : sv2v_autoblock_1
			reg [6:0] i_rat;
			for (i_rat = 'd0; i_rat < 'd32; i_rat = i_rat + 'd1)
				r_alloc_rat[i_rat[4:0] * 7+:7] <= i_rat;
		end
		else if (t_rat_copy)
			r_alloc_rat <= r_retire_rat;
		else begin
			if (t_alloc && t_uop[221])
				r_alloc_rat[t_uop[226:222] * 7+:7] <= n_prf_entry;
			if (t_alloc_two && t_uop2[221])
				r_alloc_rat[t_uop2[226:222] * 7+:7] <= n_prf_entry2;
		end
	always @(posedge clk)
		if (reset) begin : sv2v_autoblock_2
			reg [6:0] i_rat;
			for (i_rat = 'd0; i_rat < 'd32; i_rat = i_rat + 'd1)
				r_retire_rat[i_rat[4:0] * 7+:7] <= i_rat;
		end
		else begin
			if (t_free_reg)
				r_retire_rat[t_rob_head[229-:5] * 7+:7] <= t_rob_head[224-:7];
			if (t_free_reg_two)
				r_retire_rat[t_rob_next_head[229-:5] * 7+:7] <= t_rob_next_head[224-:7];
		end
	always @(*) begin
		if (_sv2v_0)
			;
		t_alloc_uop = t_uop;
		t_alloc_uop2 = t_uop2;
		t_alloc_uop[244-:7] = w_rn_srcA_1;
		t_alloc_uop[236-:7] = w_rn_srcB_1;
		t_alloc_uop2[244-:7] = w_rn_srcA_2;
		t_alloc_uop2[236-:7] = w_rn_srcB_2;
		if (t_alloc) begin
			if (t_uop[221])
				t_alloc_uop[228-:7] = n_prf_entry;
			t_alloc_uop[28-:5] = r_rob_tail_ptr[4:0];
		end
		if (t_alloc_two) begin
			if (t_uop2[221])
				t_alloc_uop2[228-:7] = n_prf_entry2;
			t_alloc_uop2[28-:5] = r_rob_next_tail_ptr[4:0];
		end
	end
	reg t_next_head_br;
	always @(*) begin
		if (_sv2v_0)
			;
		t_free_reg = 1'b0;
		t_free_reg_ptr = 'd0;
		t_free_reg_two = 1'b0;
		t_free_reg_two_ptr = 'd0;
		n_retire_prf_free = r_retire_prf_free;
		n_branch_pc = r_branch_pc;
		n_target_pc = r_target_pc;
		n_took_branch = 1'b0;
		n_branch_valid = 1'b0;
		n_branch_pc_is_indirect = 1'b0;
		n_branch_fault = 1'b0;
		n_branch_pht_idx = 'd0;
		t_next_head_br = t_rob_next_head[82] & t_retire_two;
		if (t_retire) begin
			if (t_rob_head[230]) begin
				t_free_reg = 1'b1;
				t_free_reg_ptr = t_rob_head[217-:7];
				n_retire_prf_free[{1'b0, t_rob_head[223:218]}] = 1'b0;
				n_retire_prf_free[{1'b0, t_rob_head[216:211]}] = 1'b1;
			end
			if (t_retire_two && t_rob_next_head[230]) begin
				t_free_reg_two = 1'b1;
				t_free_reg_two_ptr = t_rob_next_head[217-:7];
				n_retire_prf_free[{1'b0, t_rob_next_head[223:218]}] = 1'b0;
				n_retire_prf_free[{1'b0, t_rob_next_head[216:211]}] = 1'b1;
			end
			n_branch_pc = (t_next_head_br ? t_rob_next_head[210-:64] : t_rob_head[210-:64]);
			n_target_pc = (t_next_head_br ? t_rob_next_head[146-:64] : t_rob_head[146-:64]);
			n_took_branch = (t_next_head_br ? t_rob_next_head[80] : t_rob_head[80]);
			n_branch_valid = (t_next_head_br ? t_rob_next_head[82] : t_rob_head[82]);
			n_branch_fault = t_rob_head[241] & (t_rob_head[240] == 1'b0);
			n_branch_pht_idx = (t_next_head_br ? t_rob_next_head[15-:16] : t_rob_head[15-:16]);
			n_branch_pc_is_indirect = (t_next_head_br ? t_rob_next_head[81] : t_rob_head[81]);
		end
	end
	always @(*) begin
		if (_sv2v_0)
			;
		t_rob_tail[241] = 1'b0;
		t_rob_tail[234] = 1'b0;
		t_rob_tail[230] = 1'b0;
		t_rob_tail[229-:5] = 'd0;
		t_rob_tail[224-:7] = 'd0;
		t_rob_tail[217-:7] = 'd0;
		t_rob_tail[210-:64] = t_alloc_uop[92-:64];
		t_rob_tail[146-:64] = t_alloc_uop[92-:64] + 'd4;
		t_rob_tail[232] = (t_alloc_uop[251-:7] == 7'd65) || (t_alloc_uop[251-:7] == 7'd68);
		t_rob_tail[233] = t_alloc_uop[251-:7] == 7'd67;
		t_rob_tail[81] = (t_alloc_uop[251-:7] == 7'd68) || (t_alloc_uop[251-:7] == 7'd66);
		t_rob_tail[231] = t_alloc_uop[251-:7] == 7'd95;
		t_rob_tail[240] = 1'b0;
		t_rob_tail[239-:5] = 5'd0;
		t_rob_tail[80] = 1'b0;
		t_rob_tail[82] = t_alloc_uop[19];
		t_rob_tail[79-:64] = 'd0;
		t_rob_tail[15-:16] = t_alloc_uop[16-:16];
		t_rob_next_tail[241] = 1'b0;
		t_rob_next_tail[234] = 1'b0;
		t_rob_next_tail[230] = 1'b0;
		t_rob_next_tail[229-:5] = 'd0;
		t_rob_next_tail[224-:7] = 'd0;
		t_rob_next_tail[217-:7] = 'd0;
		t_rob_next_tail[210-:64] = t_alloc_uop2[92-:64];
		t_rob_next_tail[146-:64] = t_alloc_uop2[92-:64] + 'd4;
		t_rob_next_tail[232] = (t_alloc_uop2[251-:7] == 7'd65) || (t_alloc_uop2[251-:7] == 7'd68);
		t_rob_next_tail[233] = t_alloc_uop2[251-:7] == 7'd67;
		t_rob_next_tail[81] = (t_alloc_uop2[251-:7] == 7'd68) || (t_alloc_uop2[251-:7] == 7'd66);
		t_rob_next_tail[231] = t_alloc_uop2[251-:7] == 7'd95;
		t_rob_next_tail[239-:5] = 5'd0;
		t_rob_next_tail[240] = 1'b0;
		t_rob_next_tail[80] = 1'b0;
		t_rob_next_tail[82] = t_alloc_uop2[19];
		t_rob_next_tail[79-:64] = 'd0;
		t_rob_next_tail[15-:16] = t_alloc_uop2[16-:16];
		if (t_alloc) begin
			if (t_uop[221]) begin
				t_rob_tail[230] = 1'b1;
				t_rob_tail[229-:5] = t_uop[226:222];
				t_rob_tail[224-:7] = n_prf_entry;
				t_rob_tail[217-:7] = r_alloc_rat[t_uop[226:222] * 7+:7];
			end
			if (t_fold_uop) begin
				if (t_uop[251-:7] == 7'd96) begin
					t_rob_tail[241] = 1'b1;
					t_rob_tail[240] = 1'b1;
					t_rob_tail[239-:5] = 5'd2;
				end
				else if (t_uop[251-:7] == 7'd94) begin
					t_rob_tail[241] = 1'b1;
					t_rob_tail[240] = 1'b1;
					t_rob_tail[239-:5] = 5'd12;
				end
				else if (t_uop[251-:7] == 7'd95) begin
					t_rob_tail[241] = 1'b1;
					t_rob_tail[240] = 1'b1;
					t_rob_tail[239-:5] = w_irq_id[4:0];
				end
				else if (t_uop[251-:7] == 7'd64)
					t_rob_tail[80] = 1'b1;
			end
		end
		if (t_alloc_two) begin
			if (t_uop2[221]) begin
				t_rob_next_tail[230] = 1'b1;
				t_rob_next_tail[229-:5] = t_uop2[226:222];
				t_rob_next_tail[224-:7] = n_prf_entry2;
				t_rob_next_tail[217-:7] = (t_uop[221] && (t_uop[228-:7] == t_uop2[228-:7]) ? t_rob_tail[224-:7] : r_alloc_rat[t_uop2[226:222] * 7+:7]);
			end
			if (t_fold_uop2) begin
				if (t_uop2[251-:7] == 7'd96) begin
					t_rob_next_tail[241] = 1'b1;
					t_rob_next_tail[240] = 1'b1;
					t_rob_next_tail[239-:5] = 5'd2;
				end
				else if (t_uop2[251-:7] == 7'd94) begin
					t_rob_next_tail[241] = 1'b1;
					t_rob_next_tail[240] = 1'b1;
					t_rob_next_tail[239-:5] = 5'd12;
				end
				else if (t_uop2[251-:7] == 7'd95) begin
					t_rob_next_tail[241] = 1'b1;
					t_rob_next_tail[240] = 1'b1;
					t_rob_next_tail[239-:5] = w_irq_id[4:0];
				end
				else if (t_uop2[251-:7] == 7'd64)
					t_rob_next_tail[80] = 1'b1;
			end
		end
	end
	always @(posedge clk)
		if (reset || t_clr_rob) begin
			r_rob_complete <= 'd0;
			r_rob_sd_complete <= 'd0;
		end
		else begin
			if (t_alloc) begin
				r_rob_complete[r_rob_tail_ptr[4:0]] <= t_fold_uop;
				r_rob_sd_complete[r_rob_tail_ptr[4:0]] <= !(t_uop[18] & t_uop[229]);
			end
			if (t_alloc_two) begin
				r_rob_complete[r_rob_next_tail_ptr[4:0]] <= t_fold_uop2;
				r_rob_sd_complete[r_rob_next_tail_ptr[4:0]] <= !(t_uop2[18] & t_uop2[229]);
			end
			if (t_complete_valid_1)
				r_rob_complete[t_complete_bundle_1[141:137]] <= t_complete_bundle_1[136];
			if (t_complete_valid_2)
				r_rob_complete[t_complete_bundle_2[141:137]] <= t_complete_bundle_2[136];
			if (core_mem_rsp_valid)
				r_rob_complete[core_mem_rsp[19-:5]] <= 1'b1;
			if (t_core_store_data_ptr_valid)
				r_rob_sd_complete[t_core_store_data_ptr] <= 1'b1;
		end
	always @(posedge clk)
		if (core_mem_rsp_valid)
			r_rob_addr[core_mem_rsp[19-:5]] <= core_mem_rsp[83-:64];
	always @(posedge clk) begin
		if (t_alloc)
			r_rob[r_rob_tail_ptr[4:0]] <= t_rob_tail;
		if (t_alloc_two)
			r_rob[r_rob_next_tail_ptr[4:0]] <= t_rob_next_tail;
		if (t_complete_valid_1) begin
			r_rob[t_complete_bundle_1[141:137]][241] <= t_complete_bundle_1[135];
			r_rob[t_complete_bundle_1[141:137]][240] <= t_complete_bundle_1[64];
			r_rob[t_complete_bundle_1[141:137]][239-:5] <= t_complete_bundle_1[69-:5];
			r_rob[t_complete_bundle_1[141:137]][146-:64] <= t_complete_bundle_1[134-:64];
			r_rob[t_complete_bundle_1[141:137]][80] <= t_complete_bundle_1[70];
			r_rob[t_complete_bundle_1[141:137]][79-:64] <= t_complete_bundle_1[63-:64];
		end
		if (t_complete_valid_2) begin
			r_rob[t_complete_bundle_2[141:137]][241] <= t_complete_bundle_2[135];
			r_rob[t_complete_bundle_2[141:137]][240] <= t_complete_bundle_2[64];
			r_rob[t_complete_bundle_2[141:137]][239-:5] <= t_complete_bundle_2[69-:5];
			r_rob[t_complete_bundle_2[141:137]][146-:64] <= t_complete_bundle_2[134-:64];
			r_rob[t_complete_bundle_2[141:137]][80] <= t_complete_bundle_2[70];
			r_rob[t_complete_bundle_2[141:137]][79-:64] <= t_complete_bundle_2[63-:64];
		end
		if (core_mem_rsp_valid) begin
			r_rob[core_mem_rsp[19-:5]][79-:64] <= core_mem_rsp[147-:64];
			r_rob[core_mem_rsp[19-:5]][241] <= core_mem_rsp[1];
			r_rob[core_mem_rsp[19-:5]][239-:5] <= core_mem_rsp[6-:5];
			r_rob[core_mem_rsp[19-:5]][240] <= core_mem_rsp[1];
			r_rob[core_mem_rsp[19-:5]][234] <= core_mem_rsp[0];
		end
	end
	always @(posedge clk)
		if (reset || t_clr_rob)
			r_rob_dead_insns <= 'd0;
		else begin
			if (t_retire)
				r_rob_dead_insns[r_rob_head_ptr[4:0]] <= 1'b0;
			if (t_retire_two)
				r_rob_dead_insns[r_rob_next_head_ptr[4:0]] <= 1'b0;
			if (t_alloc)
				r_rob_dead_insns[r_rob_tail_ptr[4:0]] <= 1'b1;
			if (t_alloc_two)
				r_rob_dead_insns[r_rob_next_tail_ptr[4:0]] <= 1'b1;
		end
	always @(*) begin
		if (_sv2v_0)
			;
		t_clr_mask = uq_wait | mq_wait;
		if (t_complete_valid_1)
			t_clr_mask[t_complete_bundle_1[141-:5]] = 1'b1;
		if (t_complete_valid_2)
			t_clr_mask[t_complete_bundle_2[141-:5]] = 1'b1;
		if (core_mem_rsp_valid)
			t_clr_mask[core_mem_rsp[19-:5]] = 1'b1;
	end
	always @(posedge clk)
		if (reset)
			r_rob_inflight <= 'd0;
		else if (r_ds_done)
			r_rob_inflight <= r_rob_inflight & ~t_clr_mask;
		else begin
			if (t_complete_valid_1)
				r_rob_inflight[t_complete_bundle_1[141-:5]] <= 1'b0;
			if (t_complete_valid_2)
				r_rob_inflight[t_complete_bundle_2[141-:5]] <= 1'b0;
			if (core_mem_rsp_valid)
				r_rob_inflight[core_mem_rsp[19-:5]] <= 1'b0;
			if (t_alloc && !t_fold_uop)
				r_rob_inflight[r_rob_tail_ptr[4:0]] <= 1'b1;
			if (t_alloc_two && !t_fold_uop2)
				r_rob_inflight[r_rob_next_tail_ptr[4:0]] <= 1'b1;
		end
	always @(*) begin
		if (_sv2v_0)
			;
		n_rob_head_ptr = r_rob_head_ptr;
		n_rob_tail_ptr = r_rob_tail_ptr;
		n_rob_next_head_ptr = r_rob_next_head_ptr;
		n_rob_next_tail_ptr = r_rob_next_tail_ptr;
		if (t_clr_rob) begin
			n_rob_head_ptr = 'd0;
			n_rob_tail_ptr = 'd0;
			n_rob_next_head_ptr = 'd1;
			n_rob_next_tail_ptr = 'd1;
		end
		else begin
			if (t_alloc && !t_alloc_two) begin
				n_rob_tail_ptr = r_rob_tail_ptr + 'd1;
				n_rob_next_tail_ptr = r_rob_next_tail_ptr + 'd1;
			end
			else if (t_alloc && t_alloc_two) begin
				n_rob_tail_ptr = r_rob_tail_ptr + 'd2;
				n_rob_next_tail_ptr = r_rob_next_tail_ptr + 'd2;
			end
			if (t_retire || t_bump_rob_head) begin
				n_rob_head_ptr = (t_retire_two ? r_rob_head_ptr + 'd2 : r_rob_head_ptr + 'd1);
				n_rob_next_head_ptr = (t_retire_two ? r_rob_next_head_ptr + 'd2 : r_rob_next_head_ptr + 'd1);
			end
		end
		t_rob_empty = r_rob_head_ptr == r_rob_tail_ptr;
		t_rob_next_empty = r_rob_next_head_ptr == r_rob_tail_ptr;
		t_rob_full = (r_rob_head_ptr[4:0] == r_rob_tail_ptr[4:0]) && (r_rob_head_ptr != r_rob_tail_ptr);
		t_rob_next_full = (r_rob_head_ptr[4:0] == r_rob_next_tail_ptr[4:0]) && (r_rob_head_ptr != r_rob_next_tail_ptr);
	end
	always @(*) begin
		if (_sv2v_0)
			;
		t_rob_head = r_rob[r_rob_head_ptr[4:0]];
		t_rob_next_head = r_rob[r_rob_next_head_ptr[4:0]];
		t_rob_head_complete = r_rob_sd_complete[r_rob_head_ptr[4:0]] & r_rob_complete[r_rob_head_ptr[4:0]];
		t_rob_next_head_complete = r_rob_sd_complete[r_rob_next_head_ptr[4:0]] & r_rob_complete[r_rob_next_head_ptr[4:0]];
	end
	always @(posedge clk)
		if (reset) begin : sv2v_autoblock_3
			integer i;
			for (i = 0; i < N_PRF_ENTRIES; i = i + 1)
				begin
					r_prf_free[i] <= (i < 32 ? 1'b0 : 1'b1);
					r_retire_prf_free[i] <= (i < 32 ? 1'b0 : 1'b1);
				end
		end
		else begin
			r_prf_free <= (t_rat_copy ? r_retire_prf_free : n_prf_free);
			r_retire_prf_free <= n_retire_prf_free;
		end
	genvar _gv_i_1;
	generate
		for (_gv_i_1 = 0; _gv_i_1 < 64; _gv_i_1 = _gv_i_1 + 2) begin : genblk1
			localparam i = _gv_i_1;
			assign w_prf_free_even[i] = r_prf_free[i];
			assign w_prf_free_even[i + 1] = 1'b0;
			assign w_prf_free_odd[i] = 1'b0;
			assign w_prf_free_odd[i + 1] = r_prf_free[i + 1];
		end
	endgenerate
	genvar _gv_i_2;
	generate
		for (_gv_i_2 = 64; _gv_i_2 < N_PRF_ENTRIES; _gv_i_2 = _gv_i_2 + 2) begin : genblk2
			localparam i = _gv_i_2;
			assign w_prf_free_even[i] = 1'b0;
			assign w_prf_free_even[i + 1] = 1'b0;
			assign w_prf_free_odd[i] = 1'b0;
			assign w_prf_free_odd[i + 1] = 1'b0;
		end
	endgenerate
	assign w_prf_free_even_full = |w_prf_free_even == 1'b0;
	assign w_prf_free_odd_full = |w_prf_free_odd == 1'b0;
	find_first_set #(7) ffs_gpr(
		.in(w_prf_free_even),
		.y(w_gpr_ffs_even)
	);
	find_first_set #(7) ffs_gpr2(
		.in(w_prf_free_odd),
		.y(w_gpr_ffs_odd)
	);
	always @(posedge clk) r_bank_sel <= (reset ? 1'b0 : ~r_bank_sel);
	always @(*) begin
		if (_sv2v_0)
			;
		t_gpr_ffs = (r_bank_sel ? w_gpr_ffs_even : w_gpr_ffs_odd);
		t_gpr_ffs2 = (r_bank_sel ? w_gpr_ffs_odd : w_gpr_ffs_even);
		t_gpr_ffs_full = (r_bank_sel ? w_prf_free_even_full : w_prf_free_odd_full);
		t_gpr_ffs2_full = (r_bank_sel ? w_prf_free_odd_full : w_prf_free_even_full);
	end
	always @(*) begin
		if (_sv2v_0)
			;
		n_prf_free = r_prf_free;
		n_prf_entry = {t_uop[18], t_gpr_ffs[5:0]};
		n_prf_entry2 = {t_uop2[18], t_gpr_ffs2[5:0]};
		if (t_alloc & t_uop[221])
			n_prf_free[{1'b0, t_gpr_ffs[5:0]}] = 1'b0;
		if (t_alloc_two && t_uop2[221])
			n_prf_free[{1'b0, t_gpr_ffs2[5:0]}] = 1'b0;
		if (t_free_reg)
			n_prf_free[{1'b0, t_free_reg_ptr[5:0]}] = 1'b1;
		if (t_free_reg_two)
			n_prf_free[{1'b0, t_free_reg_two_ptr[5:0]}] = 1'b1;
	end
	decode_riscv dec0(
		.mode64(r_mode64),
		.priv(w_priv),
		.insn(insn[177-:32]),
		.page_fault(insn[145]),
		.irq(w_any_irq),
		.pc(insn[144-:64]),
		.insn_pred(insn[16]),
		.pht_idx(insn[15-:16]),
		.insn_pred_target(insn[80-:64]),
		.syscall_emu(syscall_emu),
		.uop(t_dec_uop)
	);
	decode_riscv dec1(
		.mode64(r_mode64),
		.priv(w_priv),
		.insn(insn_two[177-:32]),
		.page_fault(insn_two[145]),
		.irq(w_any_irq),
		.pc(insn_two[144-:64]),
		.insn_pred(insn_two[16]),
		.pht_idx(insn_two[15-:16]),
		.insn_pred_target(insn_two[80-:64]),
		.syscall_emu(syscall_emu),
		.uop(t_dec_uop2)
	);
	reg t_push_1;
	reg t_push_2;
	always @(*) begin
		if (_sv2v_0)
			;
		t_any_complete = (t_complete_valid_1 | core_mem_rsp_valid) | t_complete_valid_2;
		t_push_1 = t_alloc && !t_fold_uop;
		t_push_2 = t_alloc_two && !t_fold_uop2;
	end
	exec e(
		.clk(clk),
		.reset(reset),
		.putchar_fifo_out(putchar_fifo_out),
		.putchar_fifo_empty(putchar_fifo_empty),
		.putchar_fifo_pop(putchar_fifo_pop),
		.putchar_fifo_wptr(putchar_fifo_wptr),
		.putchar_fifo_rptr(putchar_fifo_rptr),
		.priv(w_priv),
		.priv_update(w_priv_update),
		.paging_active(paging_active),
		.page_table_root(page_table_root),
		.update_csr_exc(r_update_csr_exc),
		.cause(r_cause),
		.epc(r_epc),
		.tval(r_tval),
		.irq(r_irq),
		.mip(w_mip),
		.mie(w_mie),
		.mideleg(w_mideleg),
		.mstatus(w_mstatus),
		.exc_pc(w_exc_pc),
		.clear_tlb(w_exec_clear_tlb),
		.mode64(r_mode64),
		.retire(t_retire),
		.retire_two(t_retire_two),
		.divide_ready(t_divide_ready),
		.ds_done(r_ds_done),
		.mem_dq_clr(t_clr_rob),
		.restart_complete(t_restart_complete),
		.mq_wait(mq_wait),
		.uq_wait(uq_wait),
		.uq_full(t_uq_full),
		.uq_next_full(t_uq_next_full),
		.uq_uop((t_push_1 ? t_alloc_uop : t_alloc_uop2)),
		.uq_uop_two(t_alloc_uop2),
		.uq_push(t_push_1 || (!t_push_1 && t_push_2)),
		.uq_push_two(t_push_2 && t_push_1),
		.complete_bundle_1(t_complete_bundle_1),
		.complete_valid_1(t_complete_valid_1),
		.complete_bundle_2(t_complete_bundle_2),
		.complete_valid_2(t_complete_valid_2),
		.mem_req(t_mem_req),
		.mem_req_valid(t_mem_req_valid),
		.mem_req_ack(core_mem_req_ack),
		.core_store_data_valid(core_store_data_valid),
		.core_store_data(core_store_data),
		.core_store_data_ack(core_store_data_ack),
		.core_store_data_ptr_valid(t_core_store_data_ptr_valid),
		.core_store_data_ptr(t_core_store_data_ptr),
		.mem_rsp_dst_ptr(core_mem_rsp[14-:7]),
		.mem_rsp_dst_valid(core_mem_rsp[7]),
		.mem_rsp_load_data(core_mem_rsp[147-:64]),
		.mtimecmp(mtimecmp),
		.mtimecmp_val(mtimecmp_val),
		.branch_valid(r_branch_valid),
		.branch_fault(r_branch_fault),
		.counters(counters)
	);
	always @(posedge clk)
		if (reset) begin
			r_dq_head_ptr <= 'd0;
			r_dq_next_head_ptr <= 'd1;
			r_dq_next_tail_ptr <= 'd1;
			r_dq_tail_ptr <= 'd0;
			r_dq_cnt <= 'd0;
		end
		else begin
			r_dq_head_ptr <= (t_clr_rob ? 'd0 : n_dq_head_ptr);
			r_dq_tail_ptr <= (t_clr_rob ? 'd0 : n_dq_tail_ptr);
			r_dq_next_head_ptr <= (t_clr_rob ? 'd1 : n_dq_next_head_ptr);
			r_dq_next_tail_ptr <= (t_clr_rob ? 'd1 : n_dq_next_tail_ptr);
			r_dq_cnt <= (t_clr_rob ? 'd0 : n_dq_cnt);
		end
	always @(posedge clk) begin
		if (t_push_dq_one)
			r_dq[r_dq_tail_ptr[1:0]] <= t_dec_uop;
		if (t_push_dq_two)
			r_dq[r_dq_next_tail_ptr[1:0]] <= t_dec_uop2;
	end
	always @(negedge clk)
		if ((insn_ack && insn_ack_two) && 1'b0)
			$display("ack two insns in cycle %d, valid %b, %b, pc %x %x", r_cycle, insn_valid, insn_valid_two, insn[144-:64], insn_two[144-:64]);
		else if ((insn_ack && !insn_ack_two) && 1'b0)
			$display("ack one insn in cycle %d, valid %b, pc %x ", r_cycle, insn_valid, insn[144-:64]);
	always @(*) begin
		if (_sv2v_0)
			;
		t_push_dq_one = 1'b0;
		t_push_dq_two = 1'b0;
		n_dq_tail_ptr = r_dq_tail_ptr;
		n_dq_head_ptr = r_dq_head_ptr;
		n_dq_next_head_ptr = r_dq_next_head_ptr;
		n_dq_next_tail_ptr = r_dq_next_tail_ptr;
		t_dq_empty = r_dq_tail_ptr == r_dq_head_ptr;
		t_dq_next_empty = r_dq_tail_ptr == r_dq_next_head_ptr;
		t_dq_full = (r_dq_tail_ptr[1:0] == r_dq_head_ptr[1:0]) && (r_dq_tail_ptr != r_dq_head_ptr);
		t_dq_next_full = (r_dq_next_tail_ptr[1:0] == r_dq_head_ptr[1:0]) && (r_dq_next_tail_ptr != r_dq_head_ptr);
		n_dq_cnt = r_dq_cnt;
		t_uop = r_dq[r_dq_head_ptr[1:0]];
		t_uop2 = r_dq[r_dq_next_head_ptr[1:0]];
		if (t_clr_dq) begin
			n_dq_tail_ptr = 'd0;
			n_dq_head_ptr = 'd0;
			n_dq_next_head_ptr = 'd1;
			n_dq_next_tail_ptr = 'd1;
			n_dq_cnt = 'd0;
		end
		else begin
			if ((insn_valid && !t_dq_full) && !(!t_dq_next_full && insn_valid_two)) begin
				t_push_dq_one = 1'b1;
				n_dq_tail_ptr = r_dq_tail_ptr + 'd1;
				n_dq_next_tail_ptr = r_dq_next_tail_ptr + 'd1;
				n_dq_cnt = n_dq_cnt + 'd1;
			end
			else if (((insn_valid && !t_dq_full) && !t_dq_next_full) && insn_valid_two) begin
				t_push_dq_one = 1'b1;
				t_push_dq_two = 1'b1;
				n_dq_tail_ptr = r_dq_tail_ptr + 'd2;
				n_dq_next_tail_ptr = r_dq_next_tail_ptr + 'd2;
				n_dq_cnt = n_dq_cnt + 'd2;
			end
			if (t_alloc && !t_alloc_two) begin
				n_dq_head_ptr = r_dq_head_ptr + 'd1;
				n_dq_next_head_ptr = r_dq_next_head_ptr + 'd1;
				n_dq_cnt = n_dq_cnt - 'd1;
			end
			else if (t_alloc && t_alloc_two) begin
				n_dq_head_ptr = r_dq_head_ptr + 'd2;
				n_dq_next_head_ptr = r_dq_next_head_ptr + 'd2;
				n_dq_cnt = n_dq_cnt - 'd2;
			end
		end
	end
	initial _sv2v_0 = 0;
endmodule

module rf6r3w (
	clk,
	reset,
	rdptr0,
	rdptr1,
	rdptr2,
	rdptr3,
	rdptr4,
	rdptr5,
	wrptr0,
	wrptr1,
	wrptr2,
	wen0,
	wen1,
	wen2,
	wr0,
	wr1,
	wr2,
	rd0,
	rd1,
	rd2,
	rd3,
	rd4,
	rd5
);
	reg _sv2v_0;
	parameter WIDTH = 1;
	parameter LG_DEPTH = 1;
	input wire clk;
	input wire reset;
	input wire [LG_DEPTH - 1:0] rdptr0;
	input wire [LG_DEPTH - 1:0] rdptr1;
	input wire [LG_DEPTH - 1:0] rdptr2;
	input wire [LG_DEPTH - 1:0] rdptr3;
	input wire [LG_DEPTH - 1:0] rdptr4;
	input wire [LG_DEPTH - 1:0] rdptr5;
	input wire [LG_DEPTH - 1:0] wrptr0;
	input wire [LG_DEPTH - 1:0] wrptr1;
	input wire [LG_DEPTH - 1:0] wrptr2;
	input wire wen0;
	input wire wen1;
	input wire wen2;
	input wire [WIDTH - 1:0] wr0;
	input wire [WIDTH - 1:0] wr1;
	input wire [WIDTH - 1:0] wr2;
	output reg [WIDTH - 1:0] rd0;
	output reg [WIDTH - 1:0] rd1;
	output reg [WIDTH - 1:0] rd2;
	output reg [WIDTH - 1:0] rd3;
	output reg [WIDTH - 1:0] rd4;
	output reg [WIDTH - 1:0] rd5;
	localparam DEPTH = 1 << LG_DEPTH;
	localparam H_DEPTH = 1 << (LG_DEPTH - 1);
	reg [WIDTH - 1:0] r_ram_alu [H_DEPTH - 1:0];
	reg [WIDTH - 1:0] r_ram_mem [H_DEPTH - 1:0];
	wire wen2_ = wen2;
	wire [LG_DEPTH - 1:0] rdptr4_ = rdptr4;
	wire [LG_DEPTH - 1:0] rdptr5_ = rdptr5;
	wire rd0_mem = rdptr0[LG_DEPTH - 1];
	wire rd1_mem = rdptr1[LG_DEPTH - 1];
	wire rd2_mem = rdptr2[LG_DEPTH - 1];
	wire rd3_mem = rdptr3[LG_DEPTH - 1];
	wire rd4_mem = rdptr4_[LG_DEPTH - 1];
	wire rd5_mem = rdptr5_[LG_DEPTH - 1];
	reg [WIDTH - 1:0] r_rd_mem0;
	reg [WIDTH - 1:0] r_rd_mem1;
	reg [WIDTH - 1:0] r_rd_mem2;
	reg [WIDTH - 1:0] r_rd_mem3;
	reg [WIDTH - 1:0] r_rd_mem4;
	reg [WIDTH - 1:0] r_rd_mem5;
	reg [WIDTH - 1:0] r_rd_alu0;
	reg [WIDTH - 1:0] r_rd_alu1;
	reg [WIDTH - 1:0] r_rd_alu2;
	reg [WIDTH - 1:0] r_rd_alu3;
	reg [WIDTH - 1:0] r_rd_alu4;
	reg [WIDTH - 1:0] r_rd_alu5;
	reg r_rdptr0_z;
	reg r_rdptr1_z;
	reg r_rdptr2_z;
	reg r_rdptr3_z;
	reg r_rdptr4_z;
	reg r_rdptr5_z;
	reg r_rdptr0_m;
	reg r_rdptr1_m;
	reg r_rdptr2_m;
	reg r_rdptr3_m;
	reg r_rdptr4_m;
	reg r_rdptr5_m;
	always @(posedge clk) begin
		r_rdptr0_z <= rdptr0 == 'd0;
		r_rdptr1_z <= rdptr1 == 'd0;
		r_rdptr2_z <= rdptr2 == 'd0;
		r_rdptr3_z <= rdptr3 == 'd0;
		r_rdptr4_z <= rdptr4 == 'd0;
		r_rdptr5_z <= rdptr5 == 'd0;
		r_rdptr0_m <= rd0_mem;
		r_rdptr1_m <= rd1_mem;
		r_rdptr2_m <= rd2_mem;
		r_rdptr3_m <= rd3_mem;
		r_rdptr4_m <= rd4_mem;
		r_rdptr5_m <= rd5_mem;
	end
	always @(*) begin
		if (_sv2v_0)
			;
		rd0 = (r_rdptr0_z ? 'd0 : (r_rdptr0_m ? r_rd_mem0 : r_rd_alu0));
		rd1 = (r_rdptr1_z ? 'd0 : (r_rdptr1_m ? r_rd_mem1 : r_rd_alu1));
		rd2 = (r_rdptr2_z ? 'd0 : (r_rdptr2_m ? r_rd_mem2 : r_rd_alu2));
		rd3 = (r_rdptr3_z ? 'd0 : (r_rdptr3_m ? r_rd_mem3 : r_rd_alu3));
		rd4 = (r_rdptr4_z ? 'd0 : (r_rdptr4_m ? r_rd_mem4 : r_rd_alu4));
		rd5 = (r_rdptr5_z ? 'd0 : (r_rdptr5_m ? r_rd_mem5 : r_rd_alu5));
	end
	always @(posedge clk) begin
		r_rd_alu0 <= r_ram_alu[rdptr0[LG_DEPTH - 2:0]];
		r_rd_alu1 <= r_ram_alu[rdptr1[LG_DEPTH - 2:0]];
		r_rd_alu2 <= r_ram_alu[rdptr2[LG_DEPTH - 2:0]];
		r_rd_alu3 <= r_ram_alu[rdptr3[LG_DEPTH - 2:0]];
		r_rd_alu4 <= r_ram_alu[rdptr4[LG_DEPTH - 2:0]];
		r_rd_alu5 <= r_ram_alu[rdptr5[LG_DEPTH - 2:0]];
		if (wen0) begin
			if (wrptr0[LG_DEPTH - 1] == 1'b1)
				$stop;
			r_ram_alu[wrptr0[LG_DEPTH - 2:0]] <= wr0;
		end
		if (wen2_) begin
			if (wrptr2[LG_DEPTH - 1] == 1'b1)
				$stop;
			r_ram_alu[wrptr2[LG_DEPTH - 2:0]] <= wr2;
		end
	end
	always @(posedge clk) begin
		r_rd_mem0 <= r_ram_mem[rdptr0[LG_DEPTH - 2:0]];
		r_rd_mem1 <= r_ram_mem[rdptr1[LG_DEPTH - 2:0]];
		r_rd_mem2 <= r_ram_mem[rdptr2[LG_DEPTH - 2:0]];
		r_rd_mem3 <= r_ram_mem[rdptr3[LG_DEPTH - 2:0]];
		r_rd_mem4 <= r_ram_mem[rdptr4[LG_DEPTH - 2:0]];
		r_rd_mem5 <= r_ram_mem[rdptr5[LG_DEPTH - 2:0]];
		if (wen1) begin
			if (wrptr1[LG_DEPTH - 1] == 1'b0)
				$stop;
			r_ram_mem[wrptr1[LG_DEPTH - 2:0]] <= wr1;
		end
	end
	initial _sv2v_0 = 0;
endmodule

module mmu_cache (
	clk,
	reset,
	clear_tlb,
	page_table_root,
	l1i_req,
	l1i_va,
	l1d_req,
	l1d_st,
	l1d_va,
	mem_req_valid,
	mem_req_addr,
	mem_req_data,
	mem_req_store,
	mem_rsp_valid,
	mem_rsp_data,
	page_walk_rsp,
	l1d_rsp_valid,
	l1i_rsp_valid,
	l1i_gnt,
	l1d_gnt,
	core_mark_dirty_valid,
	core_mark_dirty_addr,
	core_mark_dirty_rsp_valid,
	mem_mark_valid,
	mem_mark_accessed,
	mem_mark_dirty,
	mem_mark_addr,
	mem_mark_rsp_valid,
	mmu_state
);
	reg _sv2v_0;
	input wire clk;
	input wire reset;
	input wire clear_tlb;
	input wire [63:0] page_table_root;
	input wire l1i_req;
	input wire [63:0] l1i_va;
	input wire l1d_req;
	input wire l1d_st;
	input wire [63:0] l1d_va;
	output wire mem_req_valid;
	output wire [31:0] mem_req_addr;
	output wire [63:0] mem_req_data;
	output wire mem_req_store;
	output wire mem_mark_valid;
	output wire mem_mark_accessed;
	output wire mem_mark_dirty;
	output wire [63:0] mem_mark_addr;
	input wire mem_mark_rsp_valid;
	input wire mem_rsp_valid;
	input wire [63:0] mem_rsp_data;
	output reg [71:0] page_walk_rsp;
	output wire l1d_rsp_valid;
	output wire l1i_rsp_valid;
	output wire l1i_gnt;
	output wire l1d_gnt;
	input wire core_mark_dirty_valid;
	input wire [63:0] core_mark_dirty_addr;
	output wire core_mark_dirty_rsp_valid;
	output wire [3:0] mmu_state;
	reg [63:0] n_addr;
	reg [63:0] r_addr;
	reg [63:0] n_last_addr;
	reg [63:0] r_last_addr;
	reg [63:0] n_va;
	reg [63:0] r_va;
	reg [63:0] r_pa;
	reg [63:0] n_pa;
	reg r_req;
	reg n_req;
	reg n_page_fault;
	reg r_page_fault;
	reg n_l1d_rsp_valid;
	reg r_l1d_rsp_valid;
	reg n_l1i_rsp_valid;
	reg r_l1i_rsp_valid;
	reg r_do_l1i;
	reg n_do_l1i;
	reg r_do_l1d;
	reg n_do_l1d;
	reg r_do_dirty;
	reg n_do_dirty;
	reg [1:0] n_hit_lvl;
	reg [1:0] r_hit_lvl;
	reg r_page_dirty;
	reg n_page_dirty;
	reg r_page_read;
	reg n_page_read;
	reg r_page_write;
	reg n_page_write;
	reg r_page_user;
	reg n_page_user;
	reg n_page_executable;
	reg r_page_executable;
	reg r_mem_mark_valid;
	reg n_mem_mark_valid;
	reg r_mem_mark_accessed;
	reg n_mem_mark_accessed;
	reg r_mem_mark_dirty;
	reg n_mem_mark_dirty;
	reg r_core_mark_dirty_rsp_valid;
	reg n_core_mark_dirty_rsp_valid;
	localparam LG_TLB_C_SZ = 8;
	wire [43:0] w_cache_tag;
	wire w_cache_valid;
	reg r_cache_valid;
	reg n_cache_valid;
	wire [71:0] t_cache_data;
	wire w_tlb_cache_hit = (r_cache_valid ? w_cache_valid & (w_cache_tag == r_va[63:20]) : 1'b0);
	assign mem_req_valid = r_req;
	assign mem_req_addr = r_addr[31:0];
	assign l1d_rsp_valid = r_l1d_rsp_valid;
	assign l1i_rsp_valid = r_l1i_rsp_valid;
	assign mem_mark_addr = r_last_addr;
	assign mem_mark_valid = r_mem_mark_valid;
	assign mem_mark_accessed = r_mem_mark_accessed;
	assign mem_mark_dirty = r_mem_mark_dirty;
	assign core_mark_dirty_rsp_valid = r_core_mark_dirty_rsp_valid;
	always @(*) begin
		if (_sv2v_0)
			;
		page_walk_rsp[65-:64] = r_pa;
		page_walk_rsp[71] = r_page_fault;
		page_walk_rsp[70] = r_page_dirty;
		page_walk_rsp[69] = r_page_read;
		page_walk_rsp[68] = r_page_write;
		page_walk_rsp[67] = r_page_executable;
		page_walk_rsp[66] = r_page_user;
		page_walk_rsp[1-:2] = r_hit_lvl;
	end
	assign mem_req_data = 'd0;
	reg [3:0] r_state;
	reg [3:0] n_state;
	reg n_l1i_req;
	reg r_l1i_req;
	reg n_l1d_req;
	reg r_l1d_req;
	reg n_dirty_req;
	reg r_dirty_req;
	reg n_gnt_l1i;
	reg r_gnt_l1i;
	reg n_gnt_l1d;
	reg r_gnt_l1d;
	assign mmu_state = r_state;
	assign l1i_gnt = r_gnt_l1i;
	assign l1d_gnt = r_gnt_l1d;
	wire w_lo_va = &r_va[63:39] & (r_va[39] == r_va[38]);
	wire w_hi_va = &(~r_va[63:39]) & (r_va[39] == r_va[38]);
	wire w_bad_va = (w_lo_va | w_hi_va) == 1'b0;
	reg [63:0] r_cycle;
	always @(posedge clk) r_cycle <= (reset ? 64'd0 : r_cycle + 64'd1);
	always @(negedge clk) begin
		if (clear_tlb)
			$display("tlb clear at cycle %d", r_cycle);
		if ((r_state == 4'd1) & (r_do_dirty == 1'b0))
			$display("r_va %x, w_tlb_cache_hit = %b, iside %b, dside %d at cycle %d", {r_va[63:12], 12'd0}, w_tlb_cache_hit, r_do_l1i, r_do_l1d, r_cycle);
	end
	always @(*) begin
		if (_sv2v_0)
			;
		n_l1i_req = r_l1i_req | l1i_req;
		n_l1d_req = r_l1d_req | l1d_req;
		n_dirty_req = r_dirty_req | core_mark_dirty_valid;
		n_l1d_rsp_valid = 1'b0;
		n_l1i_rsp_valid = 1'b0;
		n_addr = r_addr;
		n_last_addr = r_last_addr;
		n_mem_mark_accessed = r_mem_mark_accessed;
		n_mem_mark_valid = 1'b0;
		n_mem_mark_dirty = r_mem_mark_dirty;
		n_req = 1'b0;
		n_va = r_va;
		n_pa = r_pa;
		n_state = r_state;
		n_page_fault = 1'b0;
		n_page_dirty = 1'b0;
		n_page_executable = 1'b0;
		n_page_write = 1'b0;
		n_page_read = 1'b0;
		n_page_user = 1'b0;
		n_do_l1i = r_do_l1i;
		n_do_l1d = r_do_l1d;
		n_do_dirty = r_do_dirty;
		n_hit_lvl = r_hit_lvl;
		n_gnt_l1i = 1'b0;
		n_gnt_l1d = 1'b0;
		n_core_mark_dirty_rsp_valid = 1'b0;
		case (r_state)
			4'd0:
				if (n_l1i_req) begin
					n_state = 4'd1;
					n_va = l1i_va;
					n_l1i_req = 1'b0;
					n_do_l1i = 1'b1;
					n_do_l1d = 1'b0;
					n_do_dirty = 1'b0;
					n_gnt_l1i = 1'b1;
				end
				else if (n_l1d_req) begin
					n_state = 4'd1;
					n_va = l1d_va;
					n_l1d_req = 1'b0;
					n_do_l1i = 1'b0;
					n_do_l1d = 1'b1;
					n_do_dirty = 1'b0;
					n_gnt_l1d = 1'b1;
				end
				else if (n_dirty_req) begin
					n_do_l1i = 1'b0;
					n_do_l1d = 1'b0;
					n_dirty_req = 1'b0;
					n_do_dirty = 1'b1;
					n_state = 4'd1;
					n_va = core_mark_dirty_addr;
				end
			4'd1: begin
				n_addr = page_table_root + {52'd0, r_va[38:30], 3'd0};
				if (w_bad_va) begin
					n_state = 4'd0;
					n_page_fault = 1'b1;
					n_l1i_rsp_valid = r_do_l1i;
					n_l1d_rsp_valid = r_do_l1d;
				end
				else if (w_tlb_cache_hit & (r_do_dirty == 1'b0)) begin
					n_l1i_rsp_valid = r_do_l1i;
					n_l1d_rsp_valid = r_do_l1d;
					n_page_dirty = t_cache_data[70];
					n_page_read = t_cache_data[69];
					n_page_write = t_cache_data[68];
					n_page_executable = t_cache_data[67];
					n_page_user = t_cache_data[66];
					n_pa = t_cache_data[65-:64];
					n_hit_lvl = t_cache_data[1-:2];
					n_state = 4'd0;
				end
				else begin
					n_req = 1'b1;
					n_state = 4'd2;
				end
			end
			4'd2:
				if (mem_rsp_valid) begin
					n_addr = mem_rsp_data;
					n_last_addr = r_addr;
					if (mem_rsp_data[0] == 1'b0) begin
						n_state = 4'd0;
						n_page_fault = 1'b1;
						n_l1i_rsp_valid = r_do_l1i;
						n_l1d_rsp_valid = r_do_l1d;
					end
					else if (|mem_rsp_data[3:1]) begin
						n_hit_lvl = 2'd0;
						n_state = 4'd7;
					end
					else
						n_state = 4'd3;
				end
			4'd3: begin
				n_addr = {8'd0, r_addr[53:10], 12'd0} + {52'd0, r_va[29:21], 3'd0};
				n_req = 1'b1;
				n_state = 4'd4;
			end
			4'd4:
				if (mem_rsp_valid) begin
					n_addr = mem_rsp_data;
					n_last_addr = r_addr;
					if (mem_rsp_data[0] == 1'b0) begin
						n_state = 4'd0;
						n_page_fault = 1'b1;
						n_l1i_rsp_valid = r_do_l1i;
						n_l1d_rsp_valid = r_do_l1d;
					end
					else if (|mem_rsp_data[3:1]) begin
						n_hit_lvl = 2'd1;
						n_state = 4'd7;
					end
					else
						n_state = 4'd5;
				end
			4'd5: begin
				n_addr = {8'd0, r_addr[53:10], 12'd0} + {52'd0, r_va[20:12], 3'd0};
				n_req = 1'b1;
				n_state = 4'd6;
			end
			4'd6:
				if (mem_rsp_valid) begin
					n_addr = mem_rsp_data;
					n_last_addr = r_addr;
					if (mem_rsp_data[0] == 1'b0) begin
						n_state = 4'd0;
						n_page_fault = 1'b1;
						n_l1i_rsp_valid = r_do_l1i;
						n_l1d_rsp_valid = r_do_l1d;
					end
					else begin
						n_hit_lvl = 2'd2;
						n_state = 4'd7;
					end
				end
			4'd7: begin
				if (r_hit_lvl == 2'd2)
					n_pa = {8'd0, r_addr[53:10], 12'd0};
				else if (r_hit_lvl == 2'd1)
					n_pa = {8'd0, r_addr[53:19], r_va[20:12], 12'd0};
				else if (r_hit_lvl == 2'd0)
					n_pa = {8'd0, r_addr[53:28], r_va[29:12], 12'd0};
				n_l1i_rsp_valid = r_do_l1i;
				n_l1d_rsp_valid = r_do_l1d;
				n_page_dirty = r_addr[7];
				n_page_read = r_addr[1];
				n_page_write = r_addr[2];
				n_page_executable = r_addr[3];
				n_page_user = r_addr[4];
				if (w_tlb_cache_hit) begin
					if (n_pa != t_cache_data[65-:64])
						$display("tlb cache hit, n_pa = %x, cached pa = %x", n_pa, t_cache_data[65-:64]);
					else
						$display("tlb cache hit at cycle %d", r_cycle);
				end
				if (r_do_dirty) begin
					if (r_addr[7] == 1'b0) begin
						n_mem_mark_valid = 1'b1;
						n_mem_mark_dirty = 1'b1;
						n_state = 4'd8;
					end
					else begin
						n_core_mark_dirty_rsp_valid = 1'b1;
						n_state = 4'd0;
					end
				end
				else if (r_addr[6] == 1'b0) begin
					n_mem_mark_valid = 1'b1;
					n_mem_mark_accessed = 1'b1;
					n_state = 4'd8;
				end
				else
					n_state = 4'd0;
			end
			4'd8:
				if (mem_mark_rsp_valid) begin
					n_state = 4'd0;
					n_core_mark_dirty_rsp_valid = r_do_dirty;
					n_mem_mark_valid = 1'b0;
					n_mem_mark_dirty = 1'b0;
					n_mem_mark_accessed = 1'b0;
				end
			default:
				;
		endcase
	end
	always @(posedge clk)
		if (reset) begin
			r_state <= 4'd0;
			r_addr <= 'd0;
			r_mem_mark_valid <= 1'b0;
			r_mem_mark_accessed <= 1'b0;
			r_mem_mark_dirty <= 1'b0;
			r_last_addr <= 'd0;
			r_req <= 1'b0;
			r_va <= 'd0;
			r_pa <= 'd0;
			r_l1i_req <= 1'b0;
			r_l1d_req <= 1'b0;
			r_dirty_req <= 1'b0;
			r_l1i_rsp_valid <= 1'b0;
			r_l1d_rsp_valid <= 1'b0;
			r_page_fault <= 1'b0;
			r_page_dirty <= 1'b0;
			r_page_executable <= 1'b0;
			r_page_read <= 1'b0;
			r_page_write <= 1'b0;
			r_page_user <= 1'b0;
			r_do_l1i <= 1'b0;
			r_do_l1d <= 1'b0;
			r_do_dirty <= 1'b0;
			r_hit_lvl <= 2'd0;
			r_gnt_l1i <= 1'b0;
			r_gnt_l1d <= 1'b0;
			r_core_mark_dirty_rsp_valid <= 1'b0;
		end
		else begin
			r_state <= n_state;
			r_addr <= n_addr;
			r_mem_mark_valid <= n_mem_mark_valid;
			r_mem_mark_accessed <= n_mem_mark_accessed;
			r_mem_mark_dirty <= n_mem_mark_dirty;
			r_last_addr <= n_last_addr;
			r_req <= n_req;
			r_va <= n_va;
			r_pa <= n_pa;
			r_l1i_req <= n_l1i_req;
			r_l1d_req <= n_l1d_req;
			r_dirty_req <= n_dirty_req;
			r_l1i_rsp_valid <= n_l1i_rsp_valid;
			r_l1d_rsp_valid <= n_l1d_rsp_valid;
			r_page_fault <= n_page_fault;
			r_page_dirty <= n_page_dirty;
			r_page_executable <= n_page_executable;
			r_page_read <= n_page_read;
			r_page_write <= n_page_write;
			r_page_user <= n_page_user;
			r_do_l1i <= n_do_l1i;
			r_do_l1d <= n_do_l1d;
			r_do_dirty <= n_do_dirty;
			r_hit_lvl <= n_hit_lvl;
			r_gnt_l1i <= n_gnt_l1i;
			r_gnt_l1d <= n_gnt_l1d;
			r_core_mark_dirty_rsp_valid <= n_core_mark_dirty_rsp_valid;
		end
	reg [1:0] n_cache_state;
	reg [1:0] r_cache_state;
	reg [7:0] r_cache_cnt;
	reg [7:0] n_cache_cnt;
	reg r_cache_clr;
	reg n_cache_clr;
	always @(*) begin
		if (_sv2v_0)
			;
		n_cache_state = r_cache_state;
		n_cache_valid = r_cache_valid;
		n_cache_cnt = r_cache_cnt;
		n_cache_clr = 1'b0;
		case (r_cache_state)
			2'd0: begin
				n_cache_valid = 1'b0;
				n_cache_cnt = 'd0;
				n_cache_state = 2'd1;
			end
			2'd1: begin
				n_cache_cnt = r_cache_cnt + 'd1;
				n_cache_clr = 1'b1;
				if (clear_tlb)
					n_cache_state = 2'd0;
				else if (r_cache_cnt == 7)
					n_cache_state = 2'd2;
				else
					n_cache_state = 2'd1;
			end
			2'd2:
				if (clear_tlb)
					n_cache_state = 2'd0;
				else begin
					n_cache_valid = 1'b1;
					n_cache_state = 2'd3;
				end
			2'd3:
				if (clear_tlb)
					n_cache_state = 2'd0;
		endcase
	end
	always @(posedge clk) begin
		r_cache_state <= (reset ? 2'd0 : n_cache_state);
		r_cache_valid <= (reset ? 1'b0 : n_cache_valid);
		r_cache_cnt <= (reset ? 'd0 : n_cache_cnt);
		r_cache_clr <= (reset ? 1'b0 : n_cache_clr);
	end
	ram1r1w #(
		.WIDTH(1),
		.LG_DEPTH(LG_TLB_C_SZ)
	) tlb_valid(
		.clk(clk),
		.rd_addr(n_va[19:12]),
		.wr_addr((r_cache_clr ? r_cache_cnt : r_va[19:12])),
		.wr_data((r_cache_clr ? 1'b0 : 1'b1)),
		.wr_en(r_cache_clr | ((r_l1d_rsp_valid | r_l1i_rsp_valid) & (r_hit_lvl == 2'd2))),
		.rd_data(w_cache_valid)
	);
	ram1r1w #(
		.WIDTH(72),
		.LG_DEPTH(LG_TLB_C_SZ)
	) tlb_data(
		.clk(clk),
		.rd_addr(n_va[19:12]),
		.wr_addr(r_va[19:12]),
		.wr_data(page_walk_rsp),
		.wr_en(r_l1d_rsp_valid | r_l1i_rsp_valid),
		.rd_data(t_cache_data)
	);
	ram1r1w #(
		.WIDTH(44),
		.LG_DEPTH(LG_TLB_C_SZ)
	) tlb_tag(
		.clk(clk),
		.rd_addr(n_va[19:12]),
		.wr_addr(r_va[19:12]),
		.wr_data(r_va[63:20]),
		.wr_en(r_l1d_rsp_valid | r_l1i_rsp_valid),
		.rd_data(w_cache_tag)
	);
	initial _sv2v_0 = 0;
endmodule

module compute_pht_idx (
	pc,
	hist,
	idx
);
	input wire [63:0] pc;
	input wire [15:0] hist;
	output wire [15:0] idx;
	assign idx = hist ^ pc[17:2];
endmodule

module l2_2way (
	clk,
	reset,
	paging_active,
	l2_state,
	l1d_req_valid,
	l1d_req,
	l1d_rdy,
	l1i_req,
	l1i_addr,
	l1d_rsp_valid,
	l1i_rsp_valid,
	l1d_rsp_tag,
	l1d_rsp_addr,
	l1d_rsp_writeback,
	l1i_flush_req,
	l1d_flush_req,
	l1i_flush_complete,
	l1d_flush_complete,
	flush_complete,
	l1_mem_req_ack,
	l1_mem_load_data,
	l2_probe_addr,
	l2_probe_val,
	l2_probe_ack,
	mem_req_valid,
	mem_req_addr,
	mem_req_tag,
	mem_req_store_data,
	mem_req_opcode,
	mem_rsp_valid,
	mem_rsp_tag,
	mem_rsp_load_data,
	mmu_req_valid,
	mmu_req_addr,
	mmu_req_data,
	mmu_req_store,
	mmu_rsp_valid,
	mmu_rsp_data,
	mem_mark_valid,
	mem_mark_accessed,
	mem_mark_dirty,
	mem_mark_addr,
	mem_mark_rsp_valid,
	cache_hits,
	cache_accesses,
	l2_empty
);
	reg _sv2v_0;
	input wire clk;
	input wire reset;
	input wire paging_active;
	output wire [4:0] l2_state;
	input wire l1d_req_valid;
	input wire [168:0] l1d_req;
	output wire l1d_rdy;
	input wire l1i_req;
	input wire [31:0] l1i_addr;
	output wire l1d_rsp_valid;
	output wire l1i_rsp_valid;
	output reg [3:0] l1d_rsp_tag;
	output reg [31:0] l1d_rsp_addr;
	output reg l1d_rsp_writeback;
	input wire l1i_flush_req;
	input wire l1d_flush_req;
	input wire l1i_flush_complete;
	input wire l1d_flush_complete;
	output wire flush_complete;
	output wire l1_mem_req_ack;
	output wire l2_probe_val;
	output wire [31:0] l2_probe_addr;
	input wire l2_probe_ack;
	output wire [127:0] l1_mem_load_data;
	output wire mem_req_valid;
	output wire [31:0] mem_req_addr;
	output wire [1:0] mem_req_tag;
	output wire [127:0] mem_req_store_data;
	output wire [3:0] mem_req_opcode;
	input wire mem_rsp_valid;
	input wire [1:0] mem_rsp_tag;
	input wire [127:0] mem_rsp_load_data;
	input wire mmu_req_valid;
	input wire [31:0] mmu_req_addr;
	input wire [63:0] mmu_req_data;
	input wire mmu_req_store;
	output wire mmu_rsp_valid;
	output wire [63:0] mmu_rsp_data;
	input wire mem_mark_valid;
	input wire mem_mark_accessed;
	input wire mem_mark_dirty;
	input wire [63:0] mem_mark_addr;
	output wire mem_mark_rsp_valid;
	output wire [63:0] cache_hits;
	output wire [63:0] cache_accesses;
	output reg l2_empty;
	reg [63:0] r_mmu_rsp_data;
	reg [63:0] n_mmu_rsp_data;
	reg r_mmu_rsp_valid;
	reg n_mmu_rsp_valid;
	reg n_mem_mark_rsp_valid;
	reg r_mem_mark_rsp_valid;
	assign mmu_rsp_valid = r_mmu_rsp_valid;
	assign mmu_rsp_data = r_mmu_rsp_data;
	assign mem_mark_rsp_valid = r_mem_mark_rsp_valid;
	localparam LG_L2_LINES = 13;
	localparam L2_LINES = 8192;
	localparam TAG_BITS = 15;
	reg t_wr_dirty0;
	reg t_wr_valid0;
	reg t_wr_dirty1;
	reg t_wr_valid1;
	reg t_wr_tag0;
	reg t_wr_tag1;
	reg t_wr_d0;
	reg t_wr_d1;
	reg t_valid;
	reg t_dirty;
	reg [12:0] t_idx;
	reg [12:0] r_idx;
	reg [14:0] n_tag;
	reg [14:0] r_tag;
	reg [27:0] n_last_l1i_addr;
	reg [27:0] r_last_l1i_addr;
	reg [27:0] n_last_l1d_addr;
	reg [27:0] r_last_l1d_addr;
	reg t_gnt_l1i;
	reg t_gnt_l1d;
	reg r_l1i;
	reg r_l1d;
	reg n_l1i;
	reg n_l1d;
	reg r_wb1;
	reg n_wb1;
	reg [14:0] r_tag_wb1;
	reg [127:0] r_data_wb1;
	reg [31:0] n_addr;
	reg [31:0] r_addr;
	reg [1:0] n_rob_tag;
	reg [1:0] r_rob_tag;
	reg [31:0] n_wb_addr;
	reg [31:0] r_wb_addr;
	reg n_need_wb;
	reg r_need_wb;
	reg [31:0] n_saveaddr;
	reg [31:0] r_saveaddr;
	reg [3:0] n_opcode;
	reg [3:0] r_opcode;
	reg r_mem_req;
	reg n_mem_req;
	reg [3:0] r_mem_opcode;
	reg [3:0] n_mem_opcode;
	reg r_req_ack;
	reg n_req_ack;
	reg r_l1d_rsp_valid;
	reg n_l1d_rsp_valid;
	reg r_l1i_rsp_valid;
	reg n_l1i_rsp_valid;
	reg [127:0] r_rsp_data;
	reg [127:0] n_rsp_data;
	reg [127:0] r_store_data;
	reg [127:0] n_store_data;
	reg [3:0] r_l1d_rsp_tag;
	reg [3:0] n_l1d_rsp_tag;
	reg r_need_l1i;
	reg n_need_l1i;
	reg r_need_l1d;
	reg n_need_l1d;
	reg t_l2_flush_req;
	reg n_flush_state;
	reg r_flush_state;
	reg [2:0] n_req_ty;
	reg [2:0] r_req_ty;
	reg [4:0] n_state;
	reg [4:0] r_state;
	reg r_got_req;
	reg n_got_req;
	assign l2_state = r_state;
	reg n_flush_complete;
	reg r_flush_complete;
	reg r_flush_req;
	reg n_flush_req;
	reg [127:0] r_mem_req_store_data;
	reg [127:0] n_mem_req_store_data;
	reg [63:0] r_cache_hits;
	reg [63:0] n_cache_hits;
	reg [63:0] r_cache_accesses;
	reg [63:0] n_cache_accesses;
	reg r_replace;
	reg n_replace;
	assign flush_complete = r_flush_complete;
	assign mem_req_addr = r_addr;
	assign mem_req_tag = r_rob_tag;
	assign mem_req_valid = r_mem_req;
	assign mem_req_opcode = r_mem_opcode;
	assign mem_req_store_data = r_mem_req_store_data;
	assign l1d_rsp_valid = r_l1d_rsp_valid;
	assign l1i_rsp_valid = r_l1i_rsp_valid;
	always @(posedge clk) begin
		l1d_rsp_tag <= r_l1d_rsp_tag;
		l1d_rsp_addr <= r_saveaddr;
		l1d_rsp_writeback <= r_opcode == 4'd7;
	end
	assign l1_mem_load_data = r_rsp_data;
	assign l1_mem_req_ack = r_req_ack;
	assign cache_hits = r_cache_hits;
	assign cache_accesses = r_cache_accesses;
	reg [127:0] t_d0;
	reg [127:0] t_d1;
	wire [127:0] w_d0;
	wire [127:0] w_d1;
	wire [14:0] w_tag0;
	wire [14:0] w_tag1;
	wire w_valid0;
	wire w_dirty0;
	wire w_valid1;
	wire w_dirty1;
	reg t_last;
	reg t_wr_last;
	wire w_last;
	wire w_hit0 = (w_valid0 ? r_tag == w_tag0 : 1'b0);
	wire w_hit1 = (w_valid1 ? r_tag == w_tag1 : 1'b0);
	wire w_hit = (w_hit0 | w_hit1) & r_got_req;
	wire [127:0] w_d = (w_hit0 ? w_d0 : w_d1);
	localparam N_ROB_ENTRIES = 4;
	reg t_alloc_rob;
	reg t_pop_rob;
	reg t_is_wb;
	reg t_is_st;
	reg [2:0] r_rob_head_ptr;
	reg [2:0] n_rob_head_ptr;
	reg [2:0] r_rob_tail_ptr;
	reg [2:0] n_rob_tail_ptr;
	reg [3:0] r_rob_valid;
	reg [3:0] r_rob_done;
	reg [3:0] r_rob_hitbusy;
	reg [3:0] r_rob_was_wb;
	reg [3:0] r_rob_was_st;
	reg [3:0] r_rob_mmu_addr3;
	reg [3:0] r_rob_was_mmu;
	reg [3:0] r_rob_was_mark_dirty;
	reg [31:0] r_rob_addr [3:0];
	reg [3:0] r_rob_l1tag [3:0];
	reg r_rob_replace [3:0];
	reg [2:0] r_rob_req_ty [3:0];
	reg [127:0] r_rob_data [3:0];
	reg [127:0] r_rob_st_data [3:0];
	wire [1:0] w_rob_head_ptr = r_rob_head_ptr[1:0];
	wire [1:0] w_rob_tail_ptr = r_rob_tail_ptr[1:0];
	wire w_rob_empty = r_rob_head_ptr == r_rob_tail_ptr;
	wire w_rob_full = (r_rob_head_ptr != r_rob_tail_ptr) & (r_rob_head_ptr[1:0] == r_rob_tail_ptr[1:0]);
	wire w_need_wb0 = (w_valid0 ? w_dirty0 : 1'b0);
	wire w_need_wb1 = (w_valid1 ? w_dirty1 : 1'b0);
	wire w_need_wb = w_need_wb0 | w_need_wb1;
	reg n_mmu_mark_req;
	reg r_mmu_mark_req;
	reg n_mmu_mark_dirty;
	reg r_mmu_mark_dirty;
	reg n_mmu_mark_accessed;
	reg r_mmu_mark_accessed;
	reg r_mmu_req;
	reg n_mmu_req;
	reg r_l1d_req;
	reg n_l1d_req;
	reg r_l1i_req;
	reg n_l1i_req;
	reg r_last_gnt;
	reg n_last_gnt;
	reg n_req;
	reg r_req;
	reg r_mmu_addr3;
	reg n_mmu_addr3;
	reg n_mmu;
	reg r_mmu;
	reg n_mark_pte;
	reg r_mark_pte;
	reg r_last_idle;
	reg n_last_idle;
	reg r_was_st;
	reg n_was_st;
	reg r_was_busy;
	reg n_was_busy;
	wire [127:0] w_updated_pte = (r_mmu_addr3 ? {w_d[127:72], r_mmu_mark_dirty | w_d[71], r_mmu_mark_accessed | w_d[70], w_d[69:0]} : {w_d[127:8], r_mmu_mark_dirty | w_d[7], r_mmu_mark_accessed | w_d[6], w_d[5:0]});
	wire [3:0] w_hit_rob;
	wire [3:0] w_mmu;
	wire [3:0] w_pte;
	wire [3:0] w_wb;
	wire [3:0] w_st;
	wire [3:0] w_hit_cl;
	genvar _gv_i_1;
	generate
		for (_gv_i_1 = 0; _gv_i_1 < N_ROB_ENTRIES; _gv_i_1 = _gv_i_1 + 1) begin : genblk1
			localparam i = _gv_i_1;
			assign w_hit_rob[i] = (r_rob_valid[i] ? r_rob_addr[i][31:4] == n_addr[31:4] : 1'b0);
			assign w_mmu[i] = (r_rob_valid[i] ? r_rob_was_mmu[i] : 1'b0);
			assign w_pte[i] = (r_rob_valid[i] ? r_rob_was_mark_dirty[i] : 1'b0);
			assign w_wb[i] = (r_rob_valid[i] ? r_rob_was_wb[i] : 1'b0);
			assign w_st[i] = (r_rob_valid[i] ? r_rob_was_st[i] : 1'b0);
		end
	endgenerate
	wire w_any_mmu = |w_mmu;
	wire w_any_pte = |w_pte;
	wire w_any_wb = |w_wb;
	wire w_any_st = |w_st;
	reg [1:0] r_txn_credits;
	reg [1:0] n_txn_credits;
	always @(posedge clk) r_txn_credits <= (reset ? {2 {1'b1}} : n_txn_credits);
	wire w_all_free_credits = r_txn_credits == {2 {1'b1}};
	wire w_more_than_one_free_credit = 1'b1;
	always @(*) begin
		if (_sv2v_0)
			;
		n_txn_credits = r_txn_credits;
		if (mem_req_valid & !mem_rsp_valid)
			n_txn_credits = r_txn_credits - 'd1;
		else if (!mem_req_valid & mem_rsp_valid)
			n_txn_credits = r_txn_credits + 'd1;
	end
	wire w_hit_inflight = |w_hit_rob;
	always @(posedge clk)
		if (reset) begin
			r_rob_head_ptr <= 'd0;
			r_rob_tail_ptr <= 'd0;
		end
		else begin
			r_rob_head_ptr <= n_rob_head_ptr;
			r_rob_tail_ptr <= n_rob_tail_ptr;
		end
	always @(posedge clk)
		if (reset) begin
			r_rob_valid <= 'd0;
			r_rob_done <= 'd0;
			r_rob_hitbusy <= 'd0;
			r_rob_was_wb <= 'd0;
			r_rob_was_st <= 'd0;
			r_rob_was_mmu <= 'd0;
			r_rob_was_mark_dirty <= 'd0;
		end
		else begin
			if (t_alloc_rob) begin
				r_rob_valid[r_rob_tail_ptr[1:0]] <= 1'b1;
				r_rob_done[r_rob_tail_ptr[1:0]] <= 1'b0;
				r_rob_hitbusy[r_rob_tail_ptr[1:0]] <= w_hit_inflight;
				r_rob_was_mmu[r_rob_tail_ptr[1:0]] <= n_req_ty == 3'd3;
				r_rob_was_mark_dirty[r_rob_tail_ptr[1:0]] <= n_req_ty == 3'd2;
				r_rob_was_wb[r_rob_tail_ptr[1:0]] <= t_is_wb;
				r_rob_was_st[r_rob_tail_ptr[1:0]] <= t_is_st;
				r_rob_st_data[r_rob_tail_ptr[1:0]] <= r_store_data;
				r_rob_mmu_addr3[r_rob_tail_ptr[1:0]] <= r_mmu_addr3;
			end
			if (mem_rsp_valid & (r_state != 5'd9)) begin
				r_rob_done[mem_rsp_tag] <= 1'b1;
				r_rob_data[mem_rsp_tag] <= mem_rsp_load_data;
				if (r_rob_done[mem_rsp_tag]) begin
					$display("tag %d is already done.., valid %b", mem_rsp_tag, r_rob_valid[mem_rsp_tag]);
					$stop;
				end
				if (r_rob_valid[mem_rsp_tag] == 1'b0)
					$stop;
			end
			if (t_pop_rob)
				r_rob_valid[w_rob_head_ptr] <= 1'b0;
		end
	always @(posedge clk)
		if (t_alloc_rob) begin
			r_rob_addr[w_rob_tail_ptr] <= n_addr;
			r_rob_l1tag[w_rob_tail_ptr] <= n_l1d_rsp_tag;
			r_rob_replace[w_rob_tail_ptr] <= n_replace;
			r_rob_req_ty[w_rob_tail_ptr] <= r_req_ty;
		end
	always @(*) begin
		if (_sv2v_0)
			;
		n_rob_head_ptr = r_rob_head_ptr;
		n_rob_tail_ptr = r_rob_tail_ptr;
		if (t_alloc_rob)
			n_rob_tail_ptr = r_rob_tail_ptr + 'd1;
		if (t_pop_rob)
			n_rob_head_ptr = r_rob_head_ptr + 'd1;
	end
	always @(posedge clk)
		if (reset) begin
			r_mmu_addr3 <= 1'b0;
			r_mmu <= 1'b0;
			r_was_st <= 1'b0;
			r_was_busy <= 1'b0;
			r_mark_pte <= 1'b0;
			r_mmu_rsp_data <= 'd0;
			r_mmu_rsp_valid <= 1'b0;
			r_mem_mark_rsp_valid <= 1'b0;
			r_state <= 5'd0;
			r_req_ty <= 3'd0;
			r_got_req <= 1'b0;
			r_flush_state <= 1'd0;
			r_flush_complete <= 1'b0;
			r_idx <= 'd0;
			r_tag <= 'd0;
			r_opcode <= 4'd0;
			r_addr <= 'd0;
			r_rob_tag <= 'd0;
			r_wb_addr <= 'd0;
			r_need_wb <= 1'b0;
			r_saveaddr <= 'd0;
			r_mem_req <= 1'b0;
			r_mem_opcode <= 4'd0;
			r_rsp_data <= 'd0;
			r_l1d_rsp_valid <= 1'b0;
			r_l1i_rsp_valid <= 1'b0;
			r_l1d_rsp_tag <= 'd0;
			r_req_ack <= 1'b0;
			r_store_data <= 'd0;
			r_flush_req <= 1'b0;
			r_need_l1d <= 1'b0;
			r_need_l1i <= 1'b0;
			r_cache_hits <= 'd0;
			r_cache_accesses <= 'd0;
			r_l1d_req <= 1'b0;
			r_l1i_req <= 1'b0;
			r_mmu_req <= 1'b0;
			r_mmu_mark_req <= 1'b0;
			r_last_gnt <= 1'b0;
			r_req <= 1'b0;
			r_last_l1i_addr <= 'd0;
			r_last_l1d_addr <= 'd0;
			r_mmu_mark_dirty <= 1'b0;
			r_mmu_mark_accessed <= 1'b0;
			r_replace <= 1'b0;
			r_wb1 <= 1'b0;
			r_last_idle <= 1'b0;
		end
		else begin
			r_mmu_addr3 <= n_mmu_addr3;
			r_mmu <= n_mmu;
			r_was_st <= n_was_st;
			r_was_busy <= n_was_busy;
			r_mark_pte <= n_mark_pte;
			r_mmu_rsp_data <= n_mmu_rsp_data;
			r_mmu_rsp_valid <= n_mmu_rsp_valid;
			r_l1d_rsp_tag <= n_l1d_rsp_tag;
			r_mem_mark_rsp_valid <= n_mem_mark_rsp_valid;
			r_state <= n_state;
			r_req_ty <= n_req_ty;
			r_got_req <= n_got_req;
			r_flush_state <= n_flush_state;
			r_flush_complete <= n_flush_complete;
			r_idx <= t_idx;
			r_tag <= n_tag;
			r_opcode <= n_opcode;
			r_addr <= n_addr;
			r_rob_tag <= n_rob_tag;
			r_wb_addr <= n_wb_addr;
			r_need_wb <= n_need_wb;
			r_saveaddr <= n_saveaddr;
			r_mem_req <= n_mem_req;
			r_mem_opcode <= n_mem_opcode;
			r_rsp_data <= n_rsp_data;
			r_l1d_rsp_valid <= n_l1d_rsp_valid;
			r_l1i_rsp_valid <= n_l1i_rsp_valid;
			r_req_ack <= n_req_ack;
			r_store_data <= n_store_data;
			r_flush_req <= n_flush_req;
			r_need_l1i <= n_need_l1i;
			r_need_l1d <= n_need_l1d;
			r_cache_hits <= n_cache_hits;
			r_cache_accesses <= n_cache_accesses;
			r_l1d_req <= n_l1d_req;
			r_l1i_req <= n_l1i_req;
			r_mmu_req <= n_mmu_req;
			r_mmu_mark_req <= n_mmu_mark_req;
			r_last_gnt <= n_last_gnt;
			r_req <= n_req;
			r_last_l1i_addr <= n_last_l1i_addr;
			r_last_l1d_addr <= n_last_l1d_addr;
			r_mmu_mark_dirty <= n_mmu_mark_dirty;
			r_mmu_mark_accessed <= n_mmu_mark_accessed;
			r_replace <= n_replace;
			r_wb1 <= n_wb1;
			r_last_idle <= n_last_idle;
		end
	always @(posedge clk) r_mem_req_store_data <= n_mem_req_store_data;
	always @(*) begin
		if (_sv2v_0)
			;
		n_flush_state = r_flush_state;
		n_need_l1d = r_need_l1d | l1d_flush_req;
		n_need_l1i = r_need_l1i | l1i_flush_req;
		t_l2_flush_req = 1'b0;
		case (r_flush_state)
			1'd0:
				if (n_need_l1i | n_need_l1d)
					n_flush_state = 1'd1;
			1'd1: begin
				if (r_need_l1d && l1d_flush_complete)
					n_need_l1d = 1'b0;
				if (r_need_l1i && l1i_flush_complete)
					n_need_l1i = 1'b0;
				if ((n_need_l1d == 1'b0) && (n_need_l1i == 1'b0)) begin
					n_flush_state = 1'd0;
					t_l2_flush_req = 1'b1;
				end
			end
		endcase
	end
	reg t_probe_mmu_req_valid;
	reg [31:0] r_l2_probe_addr;
	reg [31:0] n_l2_probe_addr;
	reg n_l2_probe_val;
	reg r_l2_probe_val;
	assign l2_probe_val = r_l2_probe_val;
	assign l2_probe_addr = r_l2_probe_addr;
	reg [63:0] r_cycle;
	always @(posedge clk) r_cycle <= (reset ? 'd0 : r_cycle + 'd1);
	reg n_pstate;
	reg r_pstate;
	reg n_l2_probe_mmu;
	reg r_l2_probe_mmu;
	always @(*) begin
		if (_sv2v_0)
			;
		n_pstate = r_pstate;
		t_probe_mmu_req_valid = 1'b0;
		n_l2_probe_val = 1'b0;
		n_l2_probe_addr = r_l2_probe_addr;
		n_l2_probe_mmu = r_l2_probe_mmu;
		case (r_pstate)
			1'd0:
				if (mmu_req_valid) begin
					n_pstate = 1'd1;
					n_l2_probe_val = 1'b1;
					n_l2_probe_addr = mmu_req_addr;
					n_l2_probe_mmu = 1'b1;
				end
			1'd1:
				if (l2_probe_ack) begin
					n_pstate = 1'd0;
					t_probe_mmu_req_valid = r_l2_probe_mmu;
					n_l2_probe_mmu = 1'b0;
				end
			default:
				;
		endcase
	end
	always @(posedge clk)
		if (n_wb1) begin
			r_tag_wb1 <= w_tag1;
			r_data_wb1 <= w_d1;
		end
	always @(posedge clk)
		if (reset) begin
			r_pstate <= 1'd0;
			r_l2_probe_val <= 1'b0;
			r_l2_probe_addr <= 'd0;
			r_l2_probe_mmu <= 1'b0;
		end
		else begin
			r_pstate <= n_pstate;
			r_l2_probe_val <= n_l2_probe_val;
			r_l2_probe_addr <= n_l2_probe_addr;
			r_l2_probe_mmu <= n_l2_probe_mmu;
		end
	localparam N_MQ_ENTRIES = 8;
	reg [168:0] r_mem_q [7:0];
	reg [3:0] r_l1d_head_ptr;
	reg [3:0] n_l1d_head_ptr;
	reg [3:0] r_l1d_tail_ptr;
	reg [3:0] n_l1d_tail_ptr;
	reg [168:0] t_l1dq;
	always @(*) begin
		if (_sv2v_0)
			;
		t_l1dq = r_mem_q[r_l1d_head_ptr[2:0]];
	end
	always @(posedge clk)
		if (reset) begin
			r_l1d_head_ptr <= 'd0;
			r_l1d_tail_ptr <= 'd0;
		end
		else begin
			r_l1d_head_ptr <= n_l1d_head_ptr;
			r_l1d_tail_ptr <= n_l1d_tail_ptr;
		end
	wire w_l1d_full = (r_l1d_head_ptr != r_l1d_tail_ptr) && (r_l1d_head_ptr[2:0] == r_l1d_tail_ptr[2:0]);
	wire [3:0] w_l1d_tail_ptr_p1 = r_l1d_tail_ptr + 'd1;
	wire w_l1d_almost_full = (r_l1d_head_ptr != w_l1d_tail_ptr_p1) && (r_l1d_head_ptr[2:0] == w_l1d_tail_ptr_p1[2:0]);
	wire w_l1d_empty = r_l1d_head_ptr == r_l1d_tail_ptr;
	assign l1d_rdy = !w_l1d_almost_full;
	always @(posedge clk)
		if (l1d_req_valid) begin
			r_mem_q[r_l1d_tail_ptr[2:0]] <= l1d_req;
			if (w_l1d_full)
				$stop;
		end
	always @(*) begin
		if (_sv2v_0)
			;
		n_l1d_head_ptr = r_l1d_head_ptr;
		n_l1d_tail_ptr = r_l1d_tail_ptr;
		if (l1d_req_valid)
			n_l1d_tail_ptr = r_l1d_tail_ptr + 'd1;
		if (t_gnt_l1d)
			n_l1d_head_ptr = r_l1d_head_ptr + 'd1;
	end
	always @(posedge clk) begin
		r_l1d <= (reset ? 1'b0 : n_l1d);
		r_l1i <= (reset ? 1'b0 : n_l1i);
	end
	wire w_mmu_req = r_mmu_req | t_probe_mmu_req_valid;
	wire w_mem_mark_valid = mem_mark_valid | r_mmu_mark_req;
	wire w_l1i_r = r_l1i_req | l1i_req;
	wire w_l1d_r = !w_l1d_empty;
	wire [12:0] w_l1i_tag = l1i_addr[16:4];
	wire [12:0] w_l1d_tag = t_l1dq[152:140];
	wire [3:0] w_hit_l1d_cl;
	wire [3:0] w_hit_l1i_cl;
	genvar _gv_i_2;
	generate
		for (_gv_i_2 = 0; _gv_i_2 < N_ROB_ENTRIES; _gv_i_2 = _gv_i_2 + 1) begin : genblk2
			localparam i = _gv_i_2;
			assign w_hit_l1d_cl[i] = (r_rob_valid[i] ? r_rob_addr[i][16:4] == w_l1d_tag : 1'b0);
			assign w_hit_l1i_cl[i] = (r_rob_valid[i] ? r_rob_addr[i][16:4] == w_l1i_tag : 1'b0);
		end
	endgenerate
	wire w_hit_any_l1d = (w_l1d_r ? |w_hit_l1d_cl : 1'b0);
	wire w_hit_any_l1i = (w_l1i_r ? |w_hit_l1i_cl : 1'b0);
	wire w_l1d_req = !w_hit_any_l1d & w_l1d_r;
	wire w_l1i_req = !w_hit_any_l1i & w_l1i_r;
	wire w_pick_l1i = (w_l1i_req & w_l1d_req ? r_last_gnt : w_l1i_req);
	wire w_pick_l1d = (w_l1i_req & w_l1d_req ? !r_last_gnt : w_l1d_req);
	reg t_can_accept_txn;
	reg [127:0] r_data;
	always @(posedge clk) r_data <= r_rob_data[w_rob_head_ptr];
	always @(*) begin
		if (_sv2v_0)
			;
		n_rsp_data = (w_hit ? w_d : 128'h000000000000000000000000deadbeef);
		n_mem_mark_rsp_valid = 1'b0;
		n_mmu_rsp_data = (r_mmu_addr3 ? w_d[127:64] : w_d[63:0]);
		n_mmu_rsp_valid = 1'b0;
		t_d0 = r_data;
		t_d1 = r_data;
		n_l1i_rsp_valid = 1'b0;
		t_can_accept_txn = 1'b0;
		if (w_hit) begin
			if (r_opcode == 4'd4) begin
				if (r_mmu)
					n_mmu_rsp_valid = 1'b1;
				else if (r_mark_pte) begin
					t_d0 = w_updated_pte;
					t_d1 = w_updated_pte;
					n_mem_mark_rsp_valid = 1'b1;
				end
				else if (r_last_gnt == 1'b0)
					n_l1i_rsp_valid = 1'b1;
			end
			else begin
				t_d0 = r_store_data;
				t_d1 = r_store_data;
			end
		end
	end
	wire w_head_of_rob_done = (!w_rob_empty & r_rob_valid[w_rob_head_ptr]) & r_rob_done[w_rob_head_ptr];
	reg r_pop_rob;
	reg r_was_rob;
	reg n_was_rob;
	always @(posedge clk) begin
		r_pop_rob <= (reset ? 1'b0 : t_pop_rob);
		r_was_rob <= (reset ? 1'b0 : n_was_rob);
	end
	wire w_debug = w_rob_full == 1'b0;
	wire w_any_req = ((((r_need_wb | n_flush_req) | w_mem_mark_valid) | w_mmu_req) | w_l1d_req) | w_l1i_req;
	always @(*) begin
		if (_sv2v_0)
			;
		l2_empty = (((r_state == 5'd1) & !w_any_req) & w_rob_empty) & w_all_free_credits;
	end
	wire w_replay = (w_head_of_rob_done & w_more_than_one_free_credit) & (r_state == 5'd1);
	always @(*) begin
		if (_sv2v_0)
			;
		n_last_gnt = r_last_gnt;
		n_l1i_req = r_l1i_req | l1i_req;
		n_l1d_req = r_l1d_req | l1d_req_valid;
		n_mmu_req = r_mmu_req | t_probe_mmu_req_valid;
		n_mmu_mark_req = mem_mark_valid | r_mmu_mark_req;
		n_req = r_req;
		n_mmu_addr3 = r_mmu_addr3;
		n_mmu = r_mmu;
		n_mark_pte = r_mark_pte;
		n_replace = r_replace;
		n_state = r_state;
		n_got_req = 1'b0;
		n_flush_complete = 1'b0;
		t_wr_valid0 = 1'b0;
		t_wr_dirty0 = 1'b0;
		t_wr_tag0 = 1'b0;
		t_wr_valid1 = 1'b0;
		t_wr_dirty1 = 1'b0;
		t_wr_tag1 = 1'b0;
		t_wr_last = 1'b0;
		t_wr_d0 = 1'b0;
		t_wr_d1 = 1'b0;
		t_idx = r_idx;
		n_tag = r_tag;
		n_opcode = r_opcode;
		n_addr = r_addr;
		n_rob_tag = r_rob_tag;
		n_wb_addr = r_wb_addr;
		n_need_wb = r_need_wb;
		n_saveaddr = r_saveaddr;
		n_req_ack = 1'b0;
		n_mem_req = 1'b0;
		n_mem_opcode = r_mem_opcode;
		t_valid = 1'b0;
		t_dirty = 1'b0;
		t_last = 1'b0;
		n_l1d_rsp_tag = r_l1d_rsp_tag;
		n_store_data = r_store_data;
		n_flush_req = r_flush_req | t_l2_flush_req;
		n_mem_req_store_data = r_mem_req_store_data;
		n_cache_hits = r_cache_hits;
		n_cache_accesses = r_cache_accesses;
		n_last_l1i_addr = r_last_l1i_addr;
		n_last_l1d_addr = r_last_l1d_addr;
		t_gnt_l1i = 1'b0;
		t_gnt_l1d = 1'b0;
		n_l1d = r_l1d;
		n_l1i = r_l1i;
		n_mmu_mark_dirty = r_mmu_mark_dirty;
		n_mmu_mark_accessed = r_mmu_mark_accessed;
		n_wb1 = r_wb1;
		n_l1d_rsp_valid = 1'b0;
		n_last_idle = 1'b0;
		t_is_wb = 1'b0;
		t_is_st = 1'b0;
		t_alloc_rob = 1'b0;
		t_pop_rob = 1'b0;
		n_req_ty = r_req_ty;
		n_was_st = r_was_st;
		n_was_busy = 1'b0;
		n_was_rob = 1'b0;
		case (r_state)
			5'd0: begin
				t_valid = 1'b0;
				t_dirty = 1'b0;
				t_last = 1'b1;
				t_wr_last = 1'b1;
				t_wr_valid0 = 1'b1;
				t_wr_dirty0 = 1'b1;
				t_wr_tag0 = 1'b1;
				t_wr_d0 = 1'b1;
				t_wr_valid1 = 1'b1;
				t_wr_dirty1 = 1'b1;
				t_wr_tag1 = 1'b1;
				t_wr_d1 = 1'b1;
				t_idx = r_idx + 'd1;
				if (r_idx == 8191) begin
					n_state = 5'd1;
					n_flush_complete = 1'b1;
				end
			end
			5'd1: begin
				t_idx = 'd0;
				n_tag = r_tag;
				n_addr = r_addr;
				n_opcode = 4'd4;
				n_store_data = r_store_data;
				n_last_idle = 1'b1;
				if (w_head_of_rob_done & w_more_than_one_free_credit) begin
					n_replace = r_rob_replace[w_rob_head_ptr];
					n_addr = r_rob_addr[w_rob_head_ptr];
					n_saveaddr = r_rob_addr[w_rob_head_ptr];
					n_tag = r_rob_addr[w_rob_head_ptr][31:17];
					t_idx = r_rob_addr[w_rob_head_ptr][16:4];
					n_l1d_rsp_tag = r_rob_l1tag[w_rob_head_ptr];
					n_mmu_addr3 = r_rob_mmu_addr3[w_rob_head_ptr];
					n_was_rob = 1'b1;
					n_was_st = 1'b0;
					n_mmu = 1'b0;
					n_store_data = r_rob_st_data[w_rob_head_ptr];
					if (r_rob_hitbusy[w_rob_head_ptr]) begin
						n_state = 5'd2;
						n_got_req = 1'b1;
						n_was_busy = 1'b1;
						case (r_rob_req_ty[w_rob_head_ptr])
							3'd0: begin
								n_state = 5'd5;
								n_addr = r_wb_addr;
								n_need_wb = 1'b0;
								n_rob_tag = w_rob_tail_ptr;
								n_req_ty = 3'd0;
							end
							3'd5: begin
								n_opcode = 4'd4;
								n_last_gnt = 1'b0;
								n_req_ty = 3'd5;
							end
							3'd4: begin
								n_opcode = (r_rob_was_st[w_rob_head_ptr] ? 4'd7 : 4'd4);
								n_last_gnt = 1'b1;
								n_req_ty = 3'd4;
							end
							3'd3: begin
								n_opcode = 4'd4;
								n_last_gnt = 1'b0;
								n_mmu = 1'b1;
							end
							default: begin
								$display("hit busy for op type %d", r_rob_req_ty[w_rob_head_ptr]);
								$stop;
							end
						endcase
					end
					else
						case (r_rob_req_ty[w_rob_head_ptr])
							3'd3: begin
								n_state = 5'd3;
								n_opcode = 4'd4;
								n_last_gnt = 1'b0;
								n_mmu = 1'b1;
							end
							3'd5: begin
								n_state = 5'd3;
								n_opcode = 4'd4;
								n_last_gnt = 1'b0;
							end
							3'd4: begin
								n_state = 5'd3;
								n_was_st = r_rob_was_st[w_rob_head_ptr];
								n_opcode = (r_rob_was_st[w_rob_head_ptr] ? 4'd7 : 4'd4);
								n_store_data = r_rob_st_data[w_rob_head_ptr];
								n_last_gnt = 1'b1;
							end
							3'd0:
								;
							default: begin
								$display("handle req type %d", r_rob_req_ty[w_rob_head_ptr]);
								$stop;
							end
						endcase
					t_pop_rob = 1'b1;
				end
				else if (w_debug & w_more_than_one_free_credit) begin
					if (r_need_wb & w_rob_empty) begin
						n_state = 5'd5;
						n_addr = r_wb_addr;
						n_need_wb = 1'b0;
						n_rob_tag = w_rob_tail_ptr;
						n_req_ty = 3'd0;
					end
					else if (n_flush_req) begin
						t_idx = 'd0;
						n_state = 5'd11;
						n_req_ty = 3'd1;
					end
					else if ((w_mem_mark_valid & w_rob_empty) & !r_need_wb) begin
						n_mmu_mark_req = 1'b0;
						n_mmu_mark_dirty = mem_mark_dirty;
						n_mmu_mark_accessed = mem_mark_accessed;
						n_mmu_addr3 = mem_mark_addr[3];
						t_idx = mem_mark_addr[16:4];
						n_tag = mem_mark_addr[31:17];
						n_addr = {mem_mark_addr[31:4], {4 {1'b0}}};
						n_saveaddr = {mem_mark_addr[31:4], {4 {1'b0}}};
						n_opcode = 4'd4;
						n_mark_pte = 1'b1;
						n_state = 5'd2;
						n_got_req = 1'b1;
						n_req_ty = 3'd2;
					end
					else if ((w_mmu_req & w_rob_empty) & !r_need_wb) begin
						n_mmu_addr3 = mmu_req_addr[3];
						t_idx = mmu_req_addr[16:4];
						n_tag = mmu_req_addr[31:17];
						n_addr = {mmu_req_addr[31:4], {4 {1'b0}}};
						n_saveaddr = {mmu_req_addr[31:4], {4 {1'b0}}};
						n_opcode = 4'd4;
						n_state = 5'd2;
						n_mmu = 1'b1;
						n_got_req = 1'b1;
						n_req_ty = 3'd3;
					end
					else if ((w_l1d_req | w_l1i_req) & !r_need_wb) begin
						n_l1d = w_pick_l1d;
						n_l1i = w_pick_l1i;
						if (w_pick_l1i) begin
							n_last_gnt = 1'b0;
							t_idx = l1i_addr[16:4];
							n_tag = l1i_addr[31:17];
							n_last_l1i_addr = l1i_addr[31:4];
							n_addr = {l1i_addr[31:4], {4 {1'b0}}};
							n_saveaddr = {l1i_addr[31:4], {4 {1'b0}}};
							n_opcode = 4'd4;
							n_l1i_req = 1'b0;
							t_gnt_l1i = 1'b1;
							n_req_ty = 3'd5;
							if (w_hit_any_l1i)
								$stop;
						end
						else if (w_pick_l1d) begin
							n_last_gnt = 1'b1;
							t_idx = t_l1dq[152:140];
							n_tag = t_l1dq[167:153];
							n_addr = {t_l1dq[167:140], {4 {1'b0}}};
							n_last_l1d_addr = t_l1dq[167:140];
							n_saveaddr = {t_l1dq[167:140], {4 {1'b0}}};
							n_store_data = t_l1dq[131-:128];
							n_opcode = t_l1dq[3-:4];
							n_l1d_req = 1'b0;
							n_l1d_rsp_tag = t_l1dq[135-:4];
							t_gnt_l1d = 1'b1;
							n_req_ty = 3'd4;
							if (w_hit_any_l1d)
								$stop;
						end
						n_req_ack = 1'b1;
						n_got_req = 1'b1;
						n_state = 5'd2;
						n_cache_accesses = r_cache_accesses + 64'd1;
						n_cache_hits = r_cache_hits + 64'd1;
					end
				end
			end
			5'd2:
				if (w_hit) begin
					t_wr_last = 1'b1;
					t_last = (w_hit0 ? 1'b0 : 1'b1);
					if (r_opcode == 4'd4) begin
						if (r_mmu) begin
							n_mmu_req = 1'b0;
							n_mmu = 1'b0;
							n_state = 5'd1;
						end
						else if (r_mark_pte) begin
							n_state = 5'd8;
							if (!(r_mmu_mark_dirty | r_mmu_mark_accessed))
								$stop;
							n_mmu_mark_dirty = 1'b0;
							n_mmu_mark_accessed = 1'b0;
							t_wr_dirty0 = w_hit0;
							t_wr_dirty1 = w_hit1;
							t_dirty = 1'b1;
							t_wr_d0 = w_hit0;
							t_wr_d1 = w_hit1;
							n_mark_pte = 1'b0;
						end
						else if (r_last_gnt) begin
							n_l1d_rsp_valid = 1'b1;
							if ((((w_l1d_req & !w_l1i_req) & (t_l1dq[3-:4] == 4'd4)) & (r_need_wb == 1'b0)) & (r_was_rob == 1'b0)) begin
								n_l1d = 1'b1;
								n_last_idle = 1'b1;
								n_last_gnt = 1'b1;
								t_idx = t_l1dq[152:140];
								n_tag = t_l1dq[167:153];
								n_addr = {t_l1dq[167:140], {4 {1'b0}}};
								n_last_l1d_addr = t_l1dq[167:140];
								n_saveaddr = {t_l1dq[167:140], {4 {1'b0}}};
								n_opcode = 4'd4;
								n_l1d_req = 1'b0;
								n_l1d_rsp_tag = t_l1dq[135-:4];
								t_gnt_l1d = 1'b1;
								n_got_req = 1'b1;
								n_req_ty = 3'd4;
							end
							else
								n_state = 5'd1;
						end
						else if ((((w_l1d_req & !w_l1i_req) & (t_l1dq[3-:4] == 4'd4)) & (r_need_wb == 1'b0)) & (r_was_rob == 1'b0)) begin
							n_l1d = 1'b1;
							n_last_idle = 1'b1;
							n_last_gnt = 1'b1;
							t_idx = t_l1dq[152:140];
							n_tag = t_l1dq[167:153];
							n_addr = {t_l1dq[167:140], {4 {1'b0}}};
							n_last_l1d_addr = t_l1dq[167:140];
							n_saveaddr = {t_l1dq[167:140], {4 {1'b0}}};
							n_opcode = 4'd4;
							n_l1d_req = 1'b0;
							n_l1d_rsp_tag = t_l1dq[135-:4];
							t_gnt_l1d = 1'b1;
							n_got_req = 1'b1;
							n_req_ty = 3'd4;
						end
						else
							n_state = 5'd1;
					end
					else if (r_opcode == 4'd7) begin
						t_wr_dirty0 = w_hit0;
						t_wr_dirty1 = w_hit1;
						t_dirty = 1'b1;
						n_state = 5'd8;
						t_wr_d0 = w_hit0;
						t_wr_d1 = w_hit1;
						n_l1d_rsp_valid = 1'b1;
					end
				end
				else begin
					t_alloc_rob = 1'b1;
					n_mmu = 1'b0;
					t_is_st = r_opcode == 4'd7;
					n_rob_tag = w_rob_tail_ptr;
					n_cache_hits = r_cache_hits - 64'd1;
					n_replace = (w_valid0 == 1'b0 ? 1'b0 : (w_valid1 == 1'b0 ? 1'b1 : ~w_last));
					t_wr_last = 1'b1;
					t_last = n_replace;
					if (n_replace) begin
						if (w_dirty1) begin
							n_mem_req_store_data = w_d1;
							n_wb_addr = {w_tag1, t_idx, {4 {1'b0}}};
							n_need_wb = 1'b1;
						end
					end
					else if (w_dirty0) begin
						n_mem_req_store_data = w_d0;
						n_wb_addr = {w_tag0, t_idx, {4 {1'b0}}};
						n_need_wb = 1'b1;
					end
					n_state = 5'd1;
					n_mem_opcode = 4'd4;
					n_mem_req = 1'b1;
				end
			5'd5: begin
				t_alloc_rob = 1'b1;
				t_is_wb = 1'b1;
				n_mem_opcode = 4'd7;
				n_mem_req = 1'b1;
				n_state = 5'd1;
			end
			5'd4: n_state = 5'd1;
			5'd6: n_state = 5'd1;
			5'd3: begin
				n_mem_req = 1'b0;
				t_valid = 1'b1;
				t_dirty = 1'b0;
				t_wr_valid0 = r_replace == 1'b0;
				t_wr_dirty0 = r_replace == 1'b0;
				t_wr_tag0 = r_replace == 1'b0;
				t_wr_d0 = r_replace == 1'b0;
				t_wr_valid1 = r_replace == 1'b1;
				t_wr_dirty1 = r_replace == 1'b1;
				t_wr_tag1 = r_replace == 1'b1;
				t_wr_d1 = r_replace == 1'b1;
				n_state = 5'd7;
			end
			5'd7: begin
				n_state = 5'd2;
				n_got_req = 1'b1;
			end
			5'd8: n_state = 5'd1;
			5'd11: begin
				n_state = 5'd12;
				t_valid = 1'b0;
				t_dirty = 1'b0;
				t_wr_valid0 = 1'b1;
				t_wr_dirty0 = 1'b1;
				t_wr_valid1 = 1'b1;
				t_wr_dirty1 = 1'b1;
			end
			5'd12: begin
				n_wb1 = w_need_wb0 & w_need_wb1;
				if (w_need_wb) begin
					n_mem_req_store_data = (w_need_wb0 ? w_d0 : w_d1);
					n_addr = {(w_need_wb0 ? w_tag0 : w_tag1), t_idx, 4'd0};
					n_mem_opcode = 4'd7;
					n_mem_req = 1'b1;
					n_state = 5'd9;
				end
				else begin
					t_idx = r_idx + 'd1;
					if (r_idx == 8191) begin
						n_state = 5'd1;
						n_flush_complete = 1'b1;
						n_flush_req = 1'b0;
					end
					else
						n_state = 5'd11;
				end
			end
			5'd9:
				if (mem_rsp_valid) begin
					if (r_wb1)
						n_state = 5'd10;
					else begin
						t_idx = r_idx + 'd1;
						if (r_idx == 8191) begin
							n_state = 5'd1;
							n_flush_complete = 1'b1;
							n_flush_req = 1'b0;
						end
						else
							n_state = 5'd11;
					end
				end
			5'd10: begin
				n_wb1 = 1'b0;
				n_mem_req_store_data = r_data_wb1;
				n_addr = {r_tag_wb1, t_idx, 4'd0};
				n_mem_opcode = 4'd7;
				n_mem_req = 1'b1;
				n_state = 5'd9;
			end
			default:
				;
		endcase
	end
	reg_ram1rw #(
		.WIDTH(1),
		.LG_DEPTH(LG_L2_LINES)
	) last_ram(
		.clk(clk),
		.addr(t_idx),
		.wr_data(t_last),
		.wr_en(t_wr_last),
		.rd_data(w_last)
	);
	reg_ram1rw #(
		.WIDTH(128),
		.LG_DEPTH(LG_L2_LINES)
	) data_ram0(
		.clk(clk),
		.addr(t_idx),
		.wr_data(t_d0),
		.wr_en(t_wr_d0),
		.rd_data(w_d0)
	);
	reg_ram1rw #(
		.WIDTH(TAG_BITS),
		.LG_DEPTH(LG_L2_LINES)
	) tag_ram0(
		.clk(clk),
		.addr(t_idx),
		.wr_data(r_tag),
		.wr_en(t_wr_tag0),
		.rd_data(w_tag0)
	);
	reg_ram1rw #(
		.WIDTH(1),
		.LG_DEPTH(LG_L2_LINES)
	) valid_ram0(
		.clk(clk),
		.addr(t_idx),
		.wr_data(t_valid),
		.wr_en(t_wr_valid0),
		.rd_data(w_valid0)
	);
	reg_ram1rw #(
		.WIDTH(1),
		.LG_DEPTH(LG_L2_LINES)
	) dirty_ram0(
		.clk(clk),
		.addr(t_idx),
		.wr_data(t_dirty),
		.wr_en(t_wr_dirty0),
		.rd_data(w_dirty0)
	);
	reg_ram1rw #(
		.WIDTH(128),
		.LG_DEPTH(LG_L2_LINES)
	) data_ram1(
		.clk(clk),
		.addr(t_idx),
		.wr_data(t_d0),
		.wr_en(t_wr_d1),
		.rd_data(w_d1)
	);
	reg_ram1rw #(
		.WIDTH(TAG_BITS),
		.LG_DEPTH(LG_L2_LINES)
	) tag_ram1(
		.clk(clk),
		.addr(t_idx),
		.wr_data(r_tag),
		.wr_en(t_wr_tag1),
		.rd_data(w_tag1)
	);
	reg_ram1rw #(
		.WIDTH(1),
		.LG_DEPTH(LG_L2_LINES)
	) valid_ram1(
		.clk(clk),
		.addr(t_idx),
		.wr_data(t_valid),
		.wr_en(t_wr_valid1),
		.rd_data(w_valid1)
	);
	reg_ram1rw #(
		.WIDTH(1),
		.LG_DEPTH(LG_L2_LINES)
	) dirty_ram1(
		.clk(clk),
		.addr(t_idx),
		.wr_data(t_dirty),
		.wr_en(t_wr_dirty1),
		.rd_data(w_dirty1)
	);
	initial _sv2v_0 = 0;
endmodule

module tlb (
	clk,
	reset,
	priv,
	clear,
	active,
	req,
	va,
	pa,
	hit,
	dirty,
	readable,
	writable,
	user,
	zero_page,
	tlb_hits,
	tlb_accesses,
	replace_va,
	replace,
	page_walk_rsp
);
	reg _sv2v_0;
	input wire clk;
	input wire reset;
	input wire [1:0] priv;
	input wire clear;
	input wire active;
	input wire req;
	input wire [63:0] va;
	output reg [31:0] pa;
	output reg hit;
	output reg dirty;
	output reg readable;
	output reg writable;
	output wire user;
	output reg zero_page;
	output reg [63:0] tlb_hits;
	output reg [63:0] tlb_accesses;
	input wire [63:0] replace_va;
	input wire replace;
	input wire [71:0] page_walk_rsp;
	parameter LG_N = 2;
	parameter ISIDE = 0;
	localparam N = 1 << LG_N;
	reg [N - 1:0] r_valid;
	reg [N - 1:0] r_dirty;
	reg [N - 1:0] r_readable;
	reg [N - 1:0] r_writable;
	reg [N - 1:0] r_executable;
	reg [N - 1:0] r_user;
	reg [1:0] r_pgsize [N - 1:0];
	reg [27:0] r_va_tags [N - 1:0];
	reg [51:0] r_pa_data [N - 1:0];
	wire [N - 1:0] w_hits4k;
	wire [N - 1:0] w_hits2m;
	wire [N - 1:0] w_hits1g;
	wire [N - 1:0] w_hits;
	wire [LG_N:0] w_idx;
	genvar _gv_i_1;
	generate
		for (_gv_i_1 = 0; _gv_i_1 < N; _gv_i_1 = _gv_i_1 + 1) begin : hits
			localparam i = _gv_i_1;
			assign w_hits4k[i] = (r_valid[i] ? (r_pgsize[i] == 2'd2) & (r_va_tags[i] == va[39:12]) : 1'b0);
			assign w_hits2m[i] = (r_valid[i] ? (r_pgsize[i] == 2'd1) & (r_va_tags[i][27:9] == va[39:21]) : 1'b0);
			assign w_hits1g[i] = (r_valid[i] ? (r_pgsize[i] == 2'd0) & (r_va_tags[i][27:18] == va[39:30]) : 1'b0);
			assign w_hits[i] = (w_hits1g[i] | w_hits2m[i]) | w_hits4k[i];
		end
	endgenerate
	reg [15:0] r_lfsr;
	reg [15:0] n_lfsr;
	always @(posedge clk) r_lfsr <= (reset ? 'd1 : n_lfsr);
	always @(*) begin
		if (_sv2v_0)
			;
		n_lfsr = r_lfsr;
		if ((active & req) & (|w_hits == 1'b0))
			n_lfsr = {r_lfsr[14:0], ((r_lfsr[15] ^ r_lfsr[13]) ^ r_lfsr[12]) ^ r_lfsr[10]};
	end
	wire [63:0] w_pa_sel = (r_pgsize[w_idx[LG_N - 1:0]] == 2'd0 ? {r_pa_data[w_idx[LG_N - 1:0]][51:18], va[29:0]} : (r_pgsize[w_idx[LG_N - 1:0]] == 2'd1 ? {r_pa_data[w_idx[LG_N - 1:0]][51:9], va[20:0]} : {r_pa_data[w_idx[LG_N - 1:0]], va[11:0]}));
	find_first_set #(.LG_N(LG_N)) ffs(
		.in(w_hits),
		.y(w_idx)
	);
	always @(*) begin
		if (_sv2v_0)
			;
		tlb_hits = 'd0;
		tlb_accesses = 'd0;
	end
	always @(posedge clk) begin
		hit <= (reset ? 1'b0 : (active ? req & |w_hits : 1'b1));
		writable <= r_writable[w_idx[LG_N - 1:0]];
		readable <= r_readable[w_idx[LG_N - 1:0]];
		dirty <= r_dirty[w_idx[LG_N - 1:0]];
		pa <= (active ? w_pa_sel[31:0] : va[31:0]);
		zero_page <= (reset ? 1'b0 : |va[39:12] == 1'b0);
	end
	reg [63:0] r_cycle;
	always @(posedge clk) r_cycle <= (reset ? 'd0 : r_cycle + 'd1);
	always @(posedge clk)
		if (reset || clear)
			r_valid <= 'd0;
		else if (replace)
			r_valid[r_lfsr[LG_N:1]] <= 1'b1;
	always @(posedge clk)
		if (replace) begin
			r_dirty[r_lfsr[LG_N:1]] <= page_walk_rsp[70];
			r_readable[r_lfsr[LG_N:1]] <= page_walk_rsp[69];
			r_writable[r_lfsr[LG_N:1]] <= page_walk_rsp[68];
			r_executable[r_lfsr[LG_N:1]] <= page_walk_rsp[67];
			r_user[r_lfsr[LG_N:1]] <= page_walk_rsp[66];
			r_va_tags[r_lfsr[LG_N:1]] <= replace_va[39:12];
			r_pgsize[r_lfsr[LG_N:1]] <= page_walk_rsp[1-:2];
			r_pa_data[r_lfsr[LG_N:1]] <= page_walk_rsp[65:14];
		end
	initial _sv2v_0 = 0;
endmodule

module victim_l1i (
	clk,
	reset,
	l1i_state,
	priv,
	page_table_root,
	paging_active,
	clear_tlb,
	mode64,
	page_walk_req_va,
	page_walk_req_valid,
	page_walk_rsp_valid,
	page_walk_rsp,
	flush_req,
	flush_complete,
	restart_pc,
	restart_src_pc,
	restart_src_is_indirect,
	restart_valid,
	restart_ack,
	retire_valid,
	retired_call,
	retired_ret,
	retire_reg_ptr,
	retire_reg_data,
	retire_reg_valid,
	branch_pc_valid,
	branch_pc,
	took_branch,
	branch_fault,
	branch_pht_idx,
	insn,
	insn_valid,
	insn_ack,
	insn_two,
	insn_valid_two,
	insn_ack_two,
	mem_req_valid,
	mem_req_addr,
	mem_req_opcode,
	mem_rsp_valid,
	mem_rsp_load_data,
	cache_accesses,
	cache_hits,
	tlb_accesses,
	tlb_hits
);
	reg _sv2v_0;
	input wire clk;
	input wire reset;
	output wire [3:0] l1i_state;
	input wire paging_active;
	input wire clear_tlb;
	input wire [1:0] priv;
	input wire [63:0] page_table_root;
	input wire mode64;
	output wire [63:0] page_walk_req_va;
	output wire page_walk_req_valid;
	input wire page_walk_rsp_valid;
	input wire [71:0] page_walk_rsp;
	input wire flush_req;
	output wire flush_complete;
	input wire [63:0] restart_pc;
	input wire [63:0] restart_src_pc;
	input wire restart_src_is_indirect;
	input wire restart_valid;
	output wire restart_ack;
	input wire retire_valid;
	input wire retired_call;
	input wire retired_ret;
	input wire [4:0] retire_reg_ptr;
	input wire [63:0] retire_reg_data;
	input wire retire_reg_valid;
	input wire branch_pc_valid;
	input wire [63:0] branch_pc;
	input wire took_branch;
	input wire branch_fault;
	input wire [15:0] branch_pht_idx;
	output reg [177:0] insn;
	output wire insn_valid;
	input wire insn_ack;
	output reg [177:0] insn_two;
	output wire insn_valid_two;
	input wire insn_ack_two;
	output wire mem_req_valid;
	localparam L1I_NUM_SETS = 256;
	localparam L1I_CL_LEN = 16;
	localparam L1I_CL_LEN_BITS = 128;
	localparam LG_WORDS_PER_CL = 2;
	localparam WORDS_PER_CL = 4;
	localparam N_TAG_BITS = 27;
	localparam IDX_START = 4;
	localparam IDX_STOP = 12;
	localparam WORD_START = 2;
	localparam WORD_STOP = 4;
	localparam N_FQ_ENTRIES = 8;
	localparam RETURN_STACK_ENTRIES = 8;
	localparam PHT_ENTRIES = 65536;
	localparam BTB_ENTRIES = 128;
	output wire [63:0] mem_req_addr;
	output wire [3:0] mem_req_opcode;
	input wire mem_rsp_valid;
	input wire [127:0] mem_rsp_load_data;
	output wire [63:0] cache_accesses;
	output wire [63:0] cache_hits;
	output wire [63:0] tlb_accesses;
	output wire [63:0] tlb_hits;
	wire in_32b_mode = mode64 == 1'b0;
	reg [26:0] t_cache_tag;
	reg [26:0] r_cache_tag;
	wire [26:0] r_tag_out;
	reg r_pht_update;
	wire [1:0] r_pht_out;
	wire [1:0] r_pht_update_out;
	reg [1:0] t_pht_val;
	reg t_do_pht_wr;
	wire [15:0] n_pht_idx;
	reg [15:0] r_pht_idx;
	reg [15:0] r_pht_update_idx;
	reg [15:0] t_retire_pht_idx;
	reg r_take_br;
	reg [63:0] r_btb [127:0];
	reg [127:0] r_btb_valid;
	wire [15:0] r_jump_out;
	reg [7:0] t_cache_idx;
	reg [7:0] r_cache_idx;
	wire [127:0] r_array_out;
	reg r_mem_req_valid;
	reg n_mem_req_valid;
	reg [63:0] r_mem_req_addr;
	reg [63:0] n_mem_req_addr;
	reg [177:0] r_fq [7:0];
	reg [3:0] r_fq_head_ptr;
	reg [3:0] n_fq_head_ptr;
	reg [3:0] r_fq_next_head_ptr;
	reg [3:0] n_fq_next_head_ptr;
	reg [3:0] r_fq_next_tail_ptr;
	reg [3:0] n_fq_next_tail_ptr;
	reg [3:0] r_fq_next3_tail_ptr;
	reg [3:0] n_fq_next3_tail_ptr;
	reg [3:0] r_fq_next4_tail_ptr;
	reg [3:0] n_fq_next4_tail_ptr;
	reg [3:0] r_fq_tail_ptr;
	reg [3:0] n_fq_tail_ptr;
	reg r_resteer_bubble;
	reg n_resteer_bubble;
	reg fq_full;
	reg fq_next_empty;
	reg fq_empty;
	reg fq_full2;
	reg fq_full3;
	reg fq_full4;
	reg [511:0] r_spec_return_stack;
	reg [511:0] r_arch_return_stack;
	reg [2:0] n_arch_rs_tos;
	reg [2:0] r_arch_rs_tos;
	reg [2:0] n_spec_rs_tos;
	reg [2:0] r_spec_rs_tos;
	reg [2:0] t_next_spec_rs_tos;
	reg [15:0] n_arch_gbl_hist;
	reg [15:0] r_arch_gbl_hist;
	reg [15:0] n_spec_gbl_hist;
	reg [15:0] r_spec_gbl_hist;
	reg [15:0] r_last_spec_gbl_hist;
	reg [1:0] t_insn_idx;
	reg [63:0] n_cache_accesses;
	reg [63:0] r_cache_accesses;
	reg [63:0] n_cache_hits;
	reg [63:0] r_cache_hits;
	reg r_hit_vb;
	reg [127:0] r_vb_line;
	reg n_use_vb;
	wire w_mem_rsp_valid = n_use_vb | mem_rsp_valid;
	wire [127:0] w_mem_rsp_load_data = (n_use_vb ? r_vb_line : mem_rsp_load_data);
	function [31:0] select_cl32;
		input reg [127:0] cl;
		input reg [1:0] pos;
		reg [31:0] w32;
		begin
			case (pos)
				2'd0: w32 = cl[31:0];
				2'd1: w32 = cl[63:32];
				2'd2: w32 = cl[95:64];
				2'd3: w32 = cl[127:96];
			endcase
			select_cl32 = w32;
		end
	endfunction
	function [3:0] select_pd;
		input reg [15:0] cl;
		input reg [1:0] pos;
		reg [3:0] j;
		begin
			case (pos)
				2'd0: j = cl[3:0];
				2'd1: j = cl[7:4];
				2'd2: j = cl[11:8];
				2'd3: j = cl[15:12];
			endcase
			select_pd = j;
		end
	endfunction
	reg [63:0] r_pc;
	reg [63:0] n_pc;
	reg [63:0] r_miss_pc;
	reg [63:0] n_miss_pc;
	reg [63:0] r_cache_pc;
	reg [63:0] n_cache_pc;
	reg [63:0] r_btb_pc;
	reg r_save_vb;
	reg n_save_vb;
	reg [3:0] n_state;
	reg [3:0] r_state;
	assign l1i_state = r_state;
	reg r_restart_req;
	reg n_restart_req;
	reg r_restart_ack;
	reg n_restart_ack;
	reg r_req;
	reg n_req;
	wire r_valid_out;
	reg t_miss;
	reg t_hit;
	reg t_tag_match;
	reg t_vb;
	reg t_push_insn;
	reg t_push_insn2;
	reg t_push_insn3;
	reg t_push_insn4;
	reg t_unaligned_fetch;
	reg n_page_fault;
	reg r_page_fault;
	reg n_tlb_miss;
	reg r_tlb_miss;
	wire [63:0] w_tlb_pc;
	wire w_tlb_hit;
	reg t_reload_tlb;
	reg t_clear_fq;
	reg r_flush_req;
	reg n_flush_req;
	reg r_flush_complete;
	reg n_flush_complete;
	reg t_take_br;
	reg t_is_cflow;
	reg t_update_spec_hist;
	reg [31:0] t_insn_data;
	reg [31:0] t_insn_data2;
	reg [31:0] t_insn_data3;
	reg [31:0] t_insn_data4;
	reg [63:0] t_jal_simm;
	reg [63:0] t_br_simm;
	reg t_is_call;
	reg t_is_ret;
	reg [2:0] t_branch_cnt;
	reg [4:0] t_branch_marker;
	reg [4:0] t_spec_branch_marker;
	reg [2:0] t_first_branch;
	reg t_init_pht;
	reg [15:0] r_init_pht_idx;
	reg [15:0] n_init_pht_idx;
	localparam PP = 32;
	localparam SEXT = 48;
	reg [177:0] t_insn;
	reg [177:0] t_insn2;
	reg [177:0] t_insn3;
	reg [177:0] t_insn4;
	reg [3:0] t_pd;
	reg [63:0] r_cycle;
	always @(posedge clk) r_cycle <= (reset ? 'd0 : r_cycle + 'd1);
	assign flush_complete = r_flush_complete;
	assign insn_valid = !fq_empty;
	assign insn_valid_two = !(fq_next_empty || fq_empty);
	assign restart_ack = r_restart_ack;
	assign mem_req_valid = r_mem_req_valid;
	assign mem_req_addr = r_mem_req_addr;
	assign mem_req_opcode = 4'd4;
	assign cache_hits = r_cache_hits;
	assign cache_accesses = r_cache_accesses;
	assign page_walk_req_valid = r_tlb_miss;
	assign page_walk_req_va = r_miss_pc;
	wire [63:0] w_restart_pc = restart_pc;
	always @(*) begin
		if (_sv2v_0)
			;
		n_fq_tail_ptr = r_fq_tail_ptr;
		n_fq_head_ptr = r_fq_head_ptr;
		n_fq_next_head_ptr = r_fq_next_head_ptr;
		n_fq_next_tail_ptr = r_fq_next_tail_ptr;
		n_fq_next3_tail_ptr = r_fq_next3_tail_ptr;
		n_fq_next4_tail_ptr = r_fq_next4_tail_ptr;
		fq_empty = r_fq_head_ptr == r_fq_tail_ptr;
		fq_next_empty = r_fq_next_head_ptr == r_fq_tail_ptr;
		fq_full = (r_fq_head_ptr != r_fq_tail_ptr) && (r_fq_head_ptr[2:0] == r_fq_tail_ptr[2:0]);
		fq_full2 = ((r_fq_head_ptr != r_fq_next_tail_ptr) && (r_fq_head_ptr[2:0] == r_fq_next_tail_ptr[2:0])) || fq_full;
		fq_full3 = ((r_fq_head_ptr != r_fq_next3_tail_ptr) && (r_fq_head_ptr[2:0] == r_fq_next3_tail_ptr[2:0])) || fq_full2;
		fq_full4 = ((r_fq_head_ptr != r_fq_next4_tail_ptr) && (r_fq_head_ptr[2:0] == r_fq_next4_tail_ptr[2:0])) || fq_full3;
		insn = r_fq[r_fq_head_ptr[2:0]];
		insn_two = r_fq[r_fq_next_head_ptr[2:0]];
		if (t_push_insn4) begin
			n_fq_tail_ptr = r_fq_tail_ptr + 'd4;
			n_fq_next_tail_ptr = r_fq_next_tail_ptr + 'd4;
			n_fq_next3_tail_ptr = r_fq_next3_tail_ptr + 'd4;
			n_fq_next4_tail_ptr = r_fq_next4_tail_ptr + 'd4;
		end
		else if (t_push_insn3) begin
			n_fq_tail_ptr = r_fq_tail_ptr + 'd3;
			n_fq_next_tail_ptr = r_fq_next_tail_ptr + 'd3;
			n_fq_next3_tail_ptr = r_fq_next3_tail_ptr + 'd3;
			n_fq_next4_tail_ptr = r_fq_next4_tail_ptr + 'd3;
		end
		else if (t_push_insn2) begin
			n_fq_tail_ptr = r_fq_tail_ptr + 'd2;
			n_fq_next_tail_ptr = r_fq_next_tail_ptr + 'd2;
			n_fq_next3_tail_ptr = r_fq_next3_tail_ptr + 'd2;
			n_fq_next4_tail_ptr = r_fq_next4_tail_ptr + 'd2;
		end
		else if (t_push_insn) begin
			n_fq_tail_ptr = r_fq_tail_ptr + 'd1;
			n_fq_next_tail_ptr = r_fq_next_tail_ptr + 'd1;
			n_fq_next3_tail_ptr = r_fq_next3_tail_ptr + 'd1;
			n_fq_next4_tail_ptr = r_fq_next4_tail_ptr + 'd1;
		end
		if (insn_ack && !insn_ack_two) begin
			n_fq_head_ptr = r_fq_head_ptr + 'd1;
			n_fq_next_head_ptr = r_fq_next_head_ptr + 'd1;
		end
		else if (insn_ack && insn_ack_two) begin
			n_fq_head_ptr = r_fq_head_ptr + 'd2;
			n_fq_next_head_ptr = r_fq_next_head_ptr + 'd2;
		end
	end
	always @(posedge clk)
		if (t_push_insn)
			r_fq[r_fq_tail_ptr[2:0]] <= t_insn;
		else if (t_push_insn2) begin
			r_fq[r_fq_tail_ptr[2:0]] <= t_insn;
			r_fq[r_fq_next_tail_ptr[2:0]] <= t_insn2;
		end
		else if (t_push_insn3) begin
			r_fq[r_fq_tail_ptr[2:0]] <= t_insn;
			r_fq[r_fq_next_tail_ptr[2:0]] <= t_insn2;
			r_fq[r_fq_next3_tail_ptr[2:0]] <= t_insn3;
		end
		else if (t_push_insn4) begin
			r_fq[r_fq_tail_ptr[2:0]] <= t_insn;
			r_fq[r_fq_next_tail_ptr[2:0]] <= t_insn2;
			r_fq[r_fq_next3_tail_ptr[2:0]] <= t_insn3;
			r_fq[r_fq_next4_tail_ptr[2:0]] <= t_insn4;
		end
	always @(posedge clk)
		if (reset)
			r_btb_valid <= 'd0;
		else if (restart_valid && restart_src_is_indirect)
			r_btb_valid[restart_src_pc[8:2]] <= 1'b1;
	always @(posedge clk)
		if (restart_valid && restart_src_is_indirect)
			r_btb[restart_src_pc[8:2]] <= restart_pc;
	always @(posedge clk) r_btb_pc <= (reset ? 'd0 : (r_btb_valid[n_cache_pc[8:2]] ? r_btb[n_cache_pc[8:2]] : 'd0));
	always @(*) begin
		if (_sv2v_0)
			;
		n_save_vb = r_save_vb;
		n_page_fault = r_page_fault;
		n_pc = r_pc;
		n_miss_pc = r_miss_pc;
		n_cache_pc = 'd0;
		n_state = r_state;
		n_restart_ack = 1'b0;
		n_flush_req = r_flush_req | flush_req;
		n_flush_complete = 1'b0;
		t_cache_idx = 'd0;
		t_cache_tag = 'd0;
		n_req = 1'b0;
		n_mem_req_valid = 1'b0;
		n_mem_req_addr = r_mem_req_addr;
		n_resteer_bubble = 1'b0;
		t_next_spec_rs_tos = r_spec_rs_tos + 'd1;
		n_restart_req = restart_valid | r_restart_req;
		t_tag_match = r_tag_out == w_tlb_pc[38:IDX_STOP];
		t_miss = r_req && !(r_valid_out && t_tag_match);
		t_vb = ((r_req && r_valid_out) && !t_tag_match) && (r_state == 4'd2);
		t_hit = r_req && (r_valid_out && t_tag_match);
		n_use_vb = 1'b0;
		t_insn_idx = r_cache_pc[3:WORD_START];
		t_pd = select_pd(r_jump_out, t_insn_idx);
		t_insn_data = select_cl32(r_array_out, t_insn_idx);
		t_insn_data2 = select_cl32(r_array_out, t_insn_idx + 2'd1);
		t_insn_data3 = select_cl32(r_array_out, t_insn_idx + 2'd2);
		t_insn_data4 = select_cl32(r_array_out, t_insn_idx + 2'd3);
		t_branch_marker = {1'b1, select_pd(r_jump_out, 'd3) != 4'd0, select_pd(r_jump_out, 'd2) != 4'd0, select_pd(r_jump_out, 'd1) != 4'd0, select_pd(r_jump_out, 'd0) != 4'd0} >> t_insn_idx;
		t_spec_branch_marker = ({1'b1, select_pd(r_jump_out, 'd3) != 4'd0, select_pd(r_jump_out, 'd2) != 4'd0, select_pd(r_jump_out, 'd1) != 4'd0, select_pd(r_jump_out, 'd0) != 4'd0} >> t_insn_idx) & {4'b1111, !((t_pd == 4'd1) && !r_pht_out[1])};
		t_first_branch = 'd7;
		casez (t_spec_branch_marker)
			5'bzzzz1: t_first_branch = 'd0;
			5'bzzz10: t_first_branch = 'd1;
			5'bzz100: t_first_branch = 'd2;
			5'bz1000: t_first_branch = 'd3;
			5'b10000: t_first_branch = 'd4;
			default: t_first_branch = 'd7;
		endcase
		t_branch_cnt = (({2'd0, select_pd(r_jump_out, 'd0) != 4'd0} + {2'd0, select_pd(r_jump_out, 'd1) != 4'd0}) + {2'd0, select_pd(r_jump_out, 'd2) != 4'd0}) + {2'd0, select_pd(r_jump_out, 'd3) != 4'd0};
		t_jal_simm = {{43 {t_insn_data[31]}}, t_insn_data[31], t_insn_data[19:12], t_insn_data[20], t_insn_data[30:21], 1'b0};
		t_br_simm = {{51 {t_insn_data[31]}}, t_insn_data[31], t_insn_data[7], t_insn_data[30:25], t_insn_data[11:8], 1'b0};
		t_clear_fq = 1'b0;
		t_push_insn = 1'b0;
		t_push_insn2 = 1'b0;
		t_push_insn3 = 1'b0;
		t_push_insn4 = 1'b0;
		t_unaligned_fetch = 1'b0;
		t_take_br = 1'b0;
		t_is_cflow = 1'b0;
		t_update_spec_hist = 1'b0;
		t_is_call = 1'b0;
		t_is_ret = 1'b0;
		t_init_pht = 1'b0;
		n_init_pht_idx = r_init_pht_idx;
		t_reload_tlb = 1'b0;
		n_tlb_miss = 1'b0;
		case (r_state)
			4'd0: n_state = 4'd7;
			4'd7: begin
				t_init_pht = 1'b1;
				n_init_pht_idx = r_init_pht_idx + 'd1;
				if (r_init_pht_idx == 65535) begin
					n_state = 4'd5;
					t_cache_idx = 0;
				end
			end
			4'd1:
				if (n_restart_req) begin
					n_restart_ack = 1'b1;
					n_restart_req = 1'b0;
					n_pc = w_restart_pc;
					n_state = 4'd2;
					t_clear_fq = 1'b1;
				end
			4'd2: begin
				t_cache_idx = r_pc[11:IDX_START];
				t_cache_tag = r_pc[38:IDX_STOP];
				n_cache_pc = r_pc;
				n_req = 1'b1;
				n_pc = r_pc + 'd4;
				if (r_resteer_bubble)
					;
				else if (n_flush_req) begin
					n_flush_req = 1'b0;
					t_clear_fq = 1'b1;
					n_state = 4'd5;
					t_cache_idx = 0;
				end
				else if (n_restart_req) begin
					n_restart_ack = 1'b1;
					n_restart_req = 1'b0;
					n_pc = w_restart_pc;
					n_req = 1'b0;
					n_state = 4'd2;
					t_clear_fq = 1'b1;
					n_page_fault = 1'b0;
				end
				else if (r_page_fault) begin
					if (!fq_full) begin
						n_page_fault = 1'b0;
						t_push_insn = 1'b1;
					end
				end
				else if ((!w_tlb_hit & r_req) && paging_active) begin
					n_state = 4'd8;
					n_pc = r_pc;
					n_miss_pc = r_cache_pc;
					n_tlb_miss = 1'b1;
				end
				else if (t_miss) begin
					n_state = (t_vb ? 4'd10 : 4'd3);
					n_mem_req_valid = !t_vb;
					n_save_vb = t_vb;
					n_mem_req_addr = (paging_active ? {w_tlb_pc[63:4], {4 {1'b0}}} : {r_cache_pc[63:4], {4 {1'b0}}});
					n_miss_pc = r_cache_pc;
					n_pc = r_pc;
				end
				else if (t_hit && !fq_full) begin
					t_update_spec_hist = t_pd != 4'd0;
					if ((t_pd == 4'd5) || (t_pd == 4'd3)) begin
						t_is_cflow = 1'b1;
						t_take_br = 1'b1;
						t_is_call = t_pd == 4'd5;
						n_pc = r_cache_pc + t_jal_simm;
					end
					else if ((t_pd == 4'd1) && r_pht_out[1]) begin
						t_is_cflow = 1'b1;
						t_take_br = 1'b1;
						n_pc = r_cache_pc + t_br_simm;
					end
					else if (t_pd == 4'd2) begin
						t_is_cflow = 1'b1;
						t_is_ret = 1'b1;
						t_take_br = 1'b1;
						n_pc = r_spec_return_stack[t_next_spec_rs_tos * 64+:64];
					end
					else if ((t_pd == 4'd4) || (t_pd == 4'd6)) begin
						t_is_cflow = 1'b1;
						t_take_br = 1'b1;
						t_is_call = t_pd == 4'd6;
						n_pc = r_btb_pc;
					end
					n_resteer_bubble = t_is_cflow;
					if (!t_is_cflow) begin
						if ((t_first_branch == 'd4) && !fq_full4) begin
							t_push_insn4 = 1'b1;
							t_cache_idx = r_cache_idx + 'd1;
							n_cache_pc = r_cache_pc + 'd16;
							t_cache_tag = n_cache_pc[38:IDX_STOP];
							n_pc = r_cache_pc + 'd20;
						end
						else if ((t_first_branch == 'd3) && !fq_full3) begin
							t_push_insn3 = 1'b1;
							n_cache_pc = r_cache_pc + 'd12;
							n_pc = r_cache_pc + 'd16;
							t_cache_tag = n_cache_pc[38:IDX_STOP];
							if (t_insn_idx != 0)
								t_cache_idx = r_cache_idx + 'd1;
						end
						else if ((t_first_branch == 'd2) && !fq_full2) begin
							t_push_insn2 = 1'b1;
							n_pc = r_cache_pc + 'd8;
							n_cache_pc = r_cache_pc + 'd8;
							t_cache_tag = n_cache_pc[38:IDX_STOP];
							n_pc = r_cache_pc + 'd12;
							if (t_insn_idx == 2)
								t_cache_idx = r_cache_idx + 'd1;
						end
						else
							t_push_insn = 1'b1;
					end
					else
						t_push_insn = 1'b1;
				end
				else if (t_hit && fq_full) begin
					n_pc = r_pc;
					n_miss_pc = r_cache_pc;
					n_state = 4'd6;
				end
			end
			4'd10: begin
				n_save_vb = 1'b0;
				if (r_hit_vb) begin
					n_state = 4'd4;
					n_use_vb = 1'b1;
				end
				else begin
					n_mem_req_valid = 1'b1;
					n_state = 4'd3;
				end
			end
			4'd3:
				if (mem_rsp_valid)
					n_state = 4'd4;
			4'd4: begin
				t_cache_idx = r_miss_pc[11:IDX_START];
				t_cache_tag = r_miss_pc[38:IDX_STOP];
				if (n_flush_req) begin
					n_flush_req = 1'b0;
					t_clear_fq = 1'b1;
					n_state = 4'd5;
					t_cache_idx = 0;
				end
				else if (n_restart_req) begin
					n_restart_ack = 1'b1;
					n_restart_req = 1'b0;
					n_pc = w_restart_pc;
					n_req = 1'b0;
					n_state = 4'd2;
					t_clear_fq = 1'b1;
					n_page_fault = 1'b0;
				end
				else if (!fq_full) begin
					n_cache_pc = r_miss_pc;
					n_req = 1'b1;
					n_state = 4'd2;
				end
			end
			4'd5: begin
				if (r_cache_idx == 255) begin
					n_flush_complete = 1'b1;
					n_state = 4'd1;
				end
				t_cache_idx = r_cache_idx + 'd1;
			end
			4'd6: begin
				t_cache_idx = r_miss_pc[11:IDX_START];
				t_cache_tag = r_miss_pc[38:IDX_STOP];
				n_cache_pc = r_miss_pc;
				if (n_flush_req) begin
					n_flush_req = 1'b0;
					t_clear_fq = 1'b1;
					n_state = 4'd5;
					t_cache_idx = 0;
				end
				else if (!fq_full) begin
					n_req = 1'b1;
					n_state = 4'd2;
				end
				else if (n_restart_req) begin
					n_restart_ack = 1'b1;
					n_restart_req = 1'b0;
					n_pc = w_restart_pc;
					n_req = 1'b0;
					n_state = 4'd2;
					t_clear_fq = 1'b1;
					n_page_fault = 1'b0;
				end
			end
			4'd8:
				if (page_walk_rsp_valid) begin
					n_page_fault = page_walk_rsp[71];
					t_reload_tlb = page_walk_rsp[71] == 1'b0;
					n_state = 4'd9;
				end
			4'd9: begin
				n_cache_pc = r_miss_pc;
				t_cache_idx = r_miss_pc[11:IDX_START];
				t_cache_tag = r_miss_pc[38:IDX_STOP];
				n_state = 4'd2;
				n_req = 1'b1;
			end
			default:
				;
		endcase
	end
	always @(*) begin
		if (_sv2v_0)
			;
		n_cache_accesses = r_cache_accesses;
		n_cache_hits = r_cache_hits;
		if (t_hit)
			n_cache_hits = r_cache_hits + 'd1;
		if (r_req)
			n_cache_accesses = r_cache_accesses + 'd1;
	end
	always @(*) begin
		if (_sv2v_0)
			;
		t_insn[177-:32] = t_insn_data;
		t_insn[145] = r_page_fault;
		t_insn[144-:64] = r_cache_pc;
		t_insn[80-:64] = n_pc;
		t_insn[16] = t_take_br;
		t_insn[15-:16] = r_pht_idx;
		t_insn2[177-:32] = t_insn_data2;
		t_insn2[145] = 1'b0;
		t_insn2[144-:64] = r_cache_pc + 'd4;
		t_insn2[80-:64] = 'd0;
		t_insn2[16] = 1'b0;
		t_insn2[15-:16] = 'd0;
		t_insn3[177-:32] = t_insn_data3;
		t_insn3[145] = 1'b0;
		t_insn3[144-:64] = r_cache_pc + 'd8;
		t_insn3[80-:64] = 'd0;
		t_insn3[16] = 1'b0;
		t_insn3[15-:16] = 'd0;
		t_insn4[177-:32] = t_insn_data4;
		t_insn4[145] = 1'b0;
		t_insn4[144-:64] = r_cache_pc + 'd12;
		t_insn4[80-:64] = 'd0;
		t_insn4[16] = 1'b0;
		t_insn4[15-:16] = 'd0;
	end
	reg t_wr_valid_ram_en;
	reg t_valid_ram_value;
	reg [7:0] t_valid_ram_idx;
	compute_pht_idx cpi0(
		.pc(n_cache_pc),
		.hist(r_spec_gbl_hist),
		.idx(n_pht_idx)
	);
	always @(*) begin
		if (_sv2v_0)
			;
		t_retire_pht_idx = branch_pht_idx;
	end
	always @(*) begin
		if (_sv2v_0)
			;
		t_wr_valid_ram_en = w_mem_rsp_valid || (r_state == 4'd5);
		t_valid_ram_value = r_state != 4'd5;
		t_valid_ram_idx = (w_mem_rsp_valid ? r_mem_req_addr[11:IDX_START] : r_cache_idx);
	end
	always @(*) begin
		if (_sv2v_0)
			;
		t_pht_val = r_pht_update_out;
		t_do_pht_wr = r_pht_update;
		case (r_pht_update_out)
			2'd0:
				if (r_take_br)
					t_pht_val = 2'd1;
				else
					t_do_pht_wr = 1'b0;
			2'd1: t_pht_val = (r_take_br ? 2'd2 : 2'd0);
			2'd2: t_pht_val = (r_take_br ? 2'd3 : 2'd1);
			2'd3:
				if (!r_take_br)
					t_pht_val = 2'd2;
				else
					t_do_pht_wr = 1'b0;
		endcase
	end
	always @(posedge clk)
		if (reset) begin
			r_pht_idx <= 'd0;
			r_last_spec_gbl_hist <= 'd0;
			r_pht_update <= 1'b0;
			r_pht_update_idx <= 'd0;
			r_take_br <= 1'b0;
		end
		else begin
			r_pht_idx <= n_pht_idx;
			r_last_spec_gbl_hist <= r_spec_gbl_hist;
			r_pht_update <= branch_pc_valid;
			r_pht_update_idx <= t_retire_pht_idx;
			r_take_br <= took_branch;
		end
	tlb #(
		.LG_N(3),
		.ISIDE(0)
	) itlb(
		.clk(clk),
		.reset(reset),
		.priv(priv),
		.clear(clear_tlb),
		.active(paging_active),
		.req(n_req),
		.va(n_cache_pc),
		.pa(w_tlb_pc),
		.hit(w_tlb_hit),
		.dirty(),
		.readable(),
		.writable(),
		.user(),
		.tlb_hits(tlb_hits),
		.tlb_accesses(tlb_accesses),
		.replace_va(r_miss_pc),
		.replace(t_reload_tlb),
		.page_walk_rsp(page_walk_rsp)
	);
	ram2r1w #(
		.WIDTH(2),
		.LG_DEPTH(16)
	) pht(
		.clk(clk),
		.rd_addr0(n_pht_idx),
		.rd_addr1(t_retire_pht_idx),
		.wr_addr((t_init_pht ? r_init_pht_idx : r_pht_update_idx)),
		.wr_data((t_init_pht ? 2'd1 : t_pht_val)),
		.wr_en(t_init_pht || t_do_pht_wr),
		.rd_data0(r_pht_out),
		.rd_data1(r_pht_update_out)
	);
	ram1r1w #(
		.WIDTH(1),
		.LG_DEPTH(8)
	) valid_array(
		.clk(clk),
		.rd_addr(t_cache_idx),
		.wr_addr(t_valid_ram_idx),
		.wr_data(t_valid_ram_value),
		.wr_en(t_wr_valid_ram_en),
		.rd_data(r_valid_out)
	);
	ram1r1w #(
		.WIDTH(N_TAG_BITS),
		.LG_DEPTH(8)
	) tag_array(
		.clk(clk),
		.rd_addr(t_cache_idx),
		.wr_addr(r_mem_req_addr[11:IDX_START]),
		.wr_data(r_mem_req_addr[38:IDX_STOP]),
		.wr_en(w_mem_rsp_valid),
		.rd_data(r_tag_out)
	);
	ram1r1w #(
		.WIDTH(L1I_CL_LEN_BITS),
		.LG_DEPTH(8)
	) insn_array(
		.clk(clk),
		.rd_addr(t_cache_idx),
		.wr_addr(r_mem_req_addr[11:IDX_START]),
		.wr_data({w_mem_rsp_load_data[127:96], w_mem_rsp_load_data[95:64], w_mem_rsp_load_data[63:32], w_mem_rsp_load_data[31:0]}),
		.wr_en(w_mem_rsp_valid),
		.rd_data(r_array_out)
	);
	wire [3:0] w_pd0;
	wire [3:0] w_pd1;
	wire [3:0] w_pd2;
	wire [3:0] w_pd3;
	predecode pd0(
		.insn(w_mem_rsp_load_data[31:0]),
		.pd(w_pd0)
	);
	predecode pd1(
		.insn(w_mem_rsp_load_data[63:32]),
		.pd(w_pd1)
	);
	predecode pd2(
		.insn(w_mem_rsp_load_data[95:64]),
		.pd(w_pd2)
	);
	predecode pd3(
		.insn(w_mem_rsp_load_data[127:96]),
		.pd(w_pd3)
	);
	ram1r1w #(
		.WIDTH(16),
		.LG_DEPTH(8)
	) pd_data(
		.clk(clk),
		.rd_addr(t_cache_idx),
		.wr_addr(r_mem_req_addr[11:IDX_START]),
		.wr_data({w_pd3, w_pd2, w_pd1, w_pd0}),
		.wr_en(w_mem_rsp_valid),
		.rd_data(r_jump_out)
	);
	always @(*) begin
		if (_sv2v_0)
			;
		n_spec_rs_tos = r_spec_rs_tos;
		if (n_restart_ack)
			n_spec_rs_tos = r_arch_rs_tos;
		else if (t_is_call)
			n_spec_rs_tos = r_spec_rs_tos - 'd1;
		else if (t_is_ret)
			n_spec_rs_tos = r_spec_rs_tos + 'd1;
	end
	always @(posedge clk)
		if (t_is_call)
			r_spec_return_stack[r_spec_rs_tos * 64+:64] <= r_cache_pc + 'd4;
		else if (n_restart_ack)
			r_spec_return_stack <= r_arch_return_stack;
	always @(posedge clk)
		if ((retire_reg_valid && retire_valid) && retired_call)
			r_arch_return_stack[r_arch_rs_tos * 64+:64] <= retire_reg_data;
	always @(*) begin
		if (_sv2v_0)
			;
		n_arch_rs_tos = r_arch_rs_tos;
		if (retire_valid && retired_call)
			n_arch_rs_tos = r_arch_rs_tos - 'd1;
		else if (retire_valid && retired_ret)
			n_arch_rs_tos = r_arch_rs_tos + 'd1;
	end
	always @(*) begin
		if (_sv2v_0)
			;
		n_spec_gbl_hist = r_spec_gbl_hist;
		if (n_restart_ack)
			n_spec_gbl_hist = n_arch_gbl_hist;
		else if (t_update_spec_hist)
			n_spec_gbl_hist = {r_spec_gbl_hist[14:0], t_take_br};
	end
	always @(*) begin
		if (_sv2v_0)
			;
		n_arch_gbl_hist = r_arch_gbl_hist;
		if (branch_pc_valid)
			n_arch_gbl_hist = {r_arch_gbl_hist[14:0], took_branch};
	end
	always @(posedge clk)
		if (reset) begin
			r_tlb_miss <= 1'b0;
			r_state <= 4'd0;
			r_save_vb <= 1'b0;
			r_page_fault <= 1'b0;
			r_init_pht_idx <= 'd0;
			r_pc <= 'd0;
			r_miss_pc <= 'd0;
			r_cache_pc <= 'd0;
			r_restart_ack <= 1'b0;
			r_cache_idx <= 'd0;
			r_cache_tag <= 'd0;
			r_req <= 1'b0;
			r_mem_req_valid <= 1'b0;
			r_mem_req_addr <= 'd0;
			r_fq_head_ptr <= 'd0;
			r_fq_next_head_ptr <= 'd1;
			r_fq_next_tail_ptr <= 'd1;
			r_fq_next3_tail_ptr <= 'd1;
			r_fq_next4_tail_ptr <= 'd1;
			r_fq_tail_ptr <= 'd0;
			r_restart_req <= 1'b0;
			r_flush_req <= 1'b0;
			r_flush_complete <= 1'b0;
			r_spec_rs_tos <= 7;
			r_arch_rs_tos <= 7;
			r_arch_gbl_hist <= 'd0;
			r_spec_gbl_hist <= 'd0;
			r_cache_hits <= 'd0;
			r_cache_accesses <= 'd0;
			r_resteer_bubble <= 1'b0;
		end
		else begin
			r_tlb_miss <= n_tlb_miss;
			r_state <= n_state;
			r_save_vb <= n_save_vb;
			r_page_fault <= n_page_fault;
			r_init_pht_idx <= n_init_pht_idx;
			r_pc <= n_pc;
			r_miss_pc <= n_miss_pc;
			r_cache_pc <= n_cache_pc;
			r_restart_ack <= n_restart_ack;
			r_cache_idx <= t_cache_idx;
			r_cache_tag <= t_cache_tag;
			r_req <= n_req;
			r_mem_req_valid <= n_mem_req_valid;
			r_mem_req_addr <= n_mem_req_addr;
			r_fq_head_ptr <= (t_clear_fq ? 'd0 : n_fq_head_ptr);
			r_fq_next_head_ptr <= (t_clear_fq ? 'd1 : n_fq_next_head_ptr);
			r_fq_next_tail_ptr <= (t_clear_fq ? 'd1 : n_fq_next_tail_ptr);
			r_fq_next3_tail_ptr <= (t_clear_fq ? 'd2 : n_fq_next3_tail_ptr);
			r_fq_next4_tail_ptr <= (t_clear_fq ? 'd3 : n_fq_next4_tail_ptr);
			r_fq_tail_ptr <= (t_clear_fq ? 'd0 : n_fq_tail_ptr);
			r_restart_req <= n_restart_req;
			r_flush_req <= n_flush_req;
			r_flush_complete <= n_flush_complete;
			r_spec_rs_tos <= n_spec_rs_tos;
			r_arch_rs_tos <= n_arch_rs_tos;
			r_arch_gbl_hist <= n_arch_gbl_hist;
			r_spec_gbl_hist <= n_spec_gbl_hist;
			r_cache_hits <= n_cache_hits;
			r_cache_accesses <= n_cache_accesses;
			r_resteer_bubble <= n_resteer_bubble;
		end
	parameter LG_VB = 6;
	localparam N_VB = 1 << LG_VB;
	reg [N_VB - 1:0] r_vb_valid;
	reg [27:0] r_vb_tags [N_VB - 1:0];
	reg [127:0] r_vb_data [N_VB - 1:0];
	wire [N_VB - 1:0] w_vb_hits;
	wire [LG_VB:0] w_vb_idx;
	genvar _gv_i_1;
	generate
		for (_gv_i_1 = 0; _gv_i_1 < N_VB; _gv_i_1 = _gv_i_1 + 1) begin : vbhits
			localparam i = _gv_i_1;
			assign w_vb_hits[i] = (r_vb_valid[i] ? r_vb_tags[i] == w_tlb_pc[31:4] : 1'b0);
		end
	endgenerate
	wire w_hit_vb = |w_vb_hits;
	always @(posedge clk)
		if (reset)
			r_hit_vb <= 1'b0;
		else
			r_hit_vb <= ((r_state == 4'd2) & t_vb ? w_hit_vb : 1'b0);
	find_first_set #(.LG_N(LG_VB)) ffs(
		.in(w_vb_hits),
		.y(w_vb_idx)
	);
	always @(posedge clk) r_vb_line <= r_vb_data[w_vb_idx[LG_VB - 1:0]];
	reg [15:0] r_lfsr;
	reg [15:0] n_lfsr;
	always @(posedge clk) r_lfsr <= (reset ? 'd1 : n_lfsr);
	always @(*) begin
		if (_sv2v_0)
			;
		n_lfsr = {r_lfsr[14:0], ((r_lfsr[15] ^ r_lfsr[13]) ^ r_lfsr[12]) ^ r_lfsr[10]};
	end
	always @(posedge clk)
		if (reset || r_flush_complete) begin
			$display("FLUSH valid");
			r_vb_valid <= 'd0;
		end
		else if (t_vb)
			r_vb_valid[r_lfsr[LG_VB:1]] <= 1'b1;
	wire [38:0] w_l1i_tagout = {r_tag_out, r_cache_idx, 4'd0};
	reg [127:0] r_old_line;
	reg [27:0] r_old_addr;
	always @(posedge clk)
		if (t_vb) begin
			r_old_addr <= w_l1i_tagout[31:4];
			r_old_line <= r_array_out;
		end
	always @(posedge clk)
		if ((r_save_vb & !r_hit_vb) & (r_state == 4'd10)) begin
			r_vb_tags[r_lfsr[LG_VB:1]] <= r_old_addr;
			r_vb_data[r_lfsr[LG_VB:1]] <= r_old_line;
		end
	initial _sv2v_0 = 0;
endmodule

module fair_sched (
	clk,
	rst,
	in,
	y
);
	reg _sv2v_0;
	parameter LG_N = 2;
	localparam N = 1 << LG_N;
	input wire clk;
	input wire rst;
	input wire [N - 1:0] in;
	output reg [LG_N:0] y;
	wire any_valid = |in;
	reg [LG_N - 1:0] r_cnt;
	wire [LG_N - 1:0] n_cnt;
	reg [(2 * N) - 1:0] t_in2;
	reg [(2 * N) - 1:0] t_in_shift;
	reg [N - 1:0] t_in;
	wire [LG_N:0] t_y;
	always @(*) begin
		if (_sv2v_0)
			;
		t_in2 = {in, in};
		t_in_shift = t_in2 << r_cnt;
		t_in = t_in_shift[(2 * N) - 1:N];
	end
	always @(posedge clk)
		if (rst)
			r_cnt <= 'd0;
		else
			r_cnt <= (any_valid ? r_cnt + 'd1 : r_cnt);
	find_first_set #(LG_N) f(
		.in(t_in),
		.y(t_y)
	);
	wire [LG_N - 1:0] w_yy = t_y[LG_N - 1:0] - r_cnt;
	always @(*) begin
		if (_sv2v_0)
			;
		y = {LG_N + 1 {1'b1}};
		if (any_valid)
			y = {1'b0, w_yy};
	end
	initial _sv2v_0 = 0;
endmodule

module l2 (
	clk,
	reset,
	l2_state,
	l1d_req,
	l1i_req,
	l1d_uc,
	l1d_addr,
	l1i_addr,
	l1d_opcode,
	l1d_rsp_valid,
	l1i_rsp_valid,
	l1i_flush_req,
	l1d_flush_req,
	l1i_flush_complete,
	l1d_flush_complete,
	flush_complete,
	l1_mem_req_ack,
	l1_mem_req_store_data,
	l1_mem_load_data,
	l2_probe_addr,
	l2_probe_val,
	l2_probe_ack,
	mem_req_valid,
	mem_req_addr,
	mem_req_store_data,
	mem_req_opcode,
	mem_rsp_valid,
	mem_rsp_load_data,
	mmu_req_valid,
	mmu_req_addr,
	mmu_req_data,
	mmu_req_store,
	mmu_rsp_valid,
	mmu_rsp_data,
	mem_mark_valid,
	mem_mark_accessed,
	mem_mark_dirty,
	mem_mark_addr,
	mem_mark_rsp_valid,
	cache_hits,
	cache_accesses
);
	reg _sv2v_0;
	input wire clk;
	input wire reset;
	output wire [3:0] l2_state;
	input wire l1d_req;
	input wire l1i_req;
	input wire l1d_uc;
	input wire [63:0] l1d_addr;
	input wire [63:0] l1i_addr;
	input wire [3:0] l1d_opcode;
	output wire l1d_rsp_valid;
	output wire l1i_rsp_valid;
	input wire l1i_flush_req;
	input wire l1d_flush_req;
	input wire l1i_flush_complete;
	input wire l1d_flush_complete;
	output wire flush_complete;
	output wire l1_mem_req_ack;
	input wire [127:0] l1_mem_req_store_data;
	output wire l2_probe_val;
	output wire [63:0] l2_probe_addr;
	input wire l2_probe_ack;
	output wire [127:0] l1_mem_load_data;
	output wire mem_req_valid;
	output wire [63:0] mem_req_addr;
	output wire [127:0] mem_req_store_data;
	output wire [3:0] mem_req_opcode;
	input wire mem_rsp_valid;
	input wire [127:0] mem_rsp_load_data;
	input wire mmu_req_valid;
	input wire [63:0] mmu_req_addr;
	input wire [63:0] mmu_req_data;
	input wire mmu_req_store;
	output wire mmu_rsp_valid;
	output wire [63:0] mmu_rsp_data;
	reg [63:0] r_mmu_rsp_data;
	reg [63:0] n_mmu_rsp_data;
	reg r_mmu_rsp_valid;
	reg n_mmu_rsp_valid;
	reg n_mem_mark_rsp_valid;
	reg r_mem_mark_rsp_valid;
	assign mmu_rsp_valid = r_mmu_rsp_valid;
	assign mmu_rsp_data = r_mmu_rsp_data;
	output wire mem_mark_rsp_valid;
	assign mem_mark_rsp_valid = r_mem_mark_rsp_valid;
	input wire mem_mark_valid;
	input wire mem_mark_accessed;
	input wire mem_mark_dirty;
	input wire [63:0] mem_mark_addr;
	output wire [63:0] cache_hits;
	output wire [63:0] cache_accesses;
	localparam LG_L2_LINES = 12;
	localparam L2_LINES = 4096;
	localparam TAG_BITS = 48;
	reg t_wr_dirty;
	reg t_wr_valid;
	reg t_wr_d0;
	wire t_wr_d1;
	wire t_wr_d2;
	wire t_wr_d3;
	reg t_wr_tag;
	reg t_valid;
	reg t_dirty;
	reg [11:0] t_idx;
	reg [11:0] r_idx;
	reg [47:0] n_tag;
	reg [47:0] r_tag;
	reg [59:0] n_last_l1i_addr;
	reg [59:0] r_last_l1i_addr;
	reg [59:0] n_last_l1d_addr;
	reg [59:0] r_last_l1d_addr;
	reg t_gnt_l1i;
	reg t_gnt_l1d;
	reg [63:0] n_addr;
	reg [63:0] r_addr;
	reg [63:0] n_saveaddr;
	reg [63:0] r_saveaddr;
	reg [3:0] n_opcode;
	reg [3:0] r_opcode;
	reg r_mem_req;
	reg n_mem_req;
	reg [3:0] r_mem_opcode;
	reg [3:0] n_mem_opcode;
	reg r_req_ack;
	reg n_req_ack;
	reg r_l1d_rsp_valid;
	reg n_l1d_rsp_valid;
	reg r_l1i_rsp_valid;
	reg n_l1i_rsp_valid;
	reg [127:0] r_rsp_data;
	reg [127:0] n_rsp_data;
	reg [127:0] r_store_data;
	reg [127:0] n_store_data;
	reg r_reload;
	reg n_reload;
	reg r_need_l1i;
	reg n_need_l1i;
	reg r_need_l1d;
	reg n_need_l1d;
	reg t_l2_flush_req;
	reg n_flush_state;
	reg r_flush_state;
	reg [4:0] n_state;
	reg [4:0] r_state;
	assign l2_state = 4'd0;
	reg n_flush_complete;
	reg r_flush_complete;
	reg r_flush_req;
	reg n_flush_req;
	reg [127:0] r_mem_req_store_data;
	reg [127:0] n_mem_req_store_data;
	reg [63:0] r_cache_hits;
	reg [63:0] n_cache_hits;
	reg [63:0] r_cache_accesses;
	reg [63:0] n_cache_accesses;
	assign flush_complete = r_flush_complete;
	assign mem_req_addr = r_addr;
	assign mem_req_valid = r_mem_req;
	assign mem_req_opcode = r_mem_opcode;
	assign mem_req_store_data = r_mem_req_store_data;
	assign l1d_rsp_valid = r_l1d_rsp_valid;
	assign l1i_rsp_valid = r_l1i_rsp_valid;
	assign l1_mem_load_data = r_rsp_data;
	assign l1_mem_req_ack = r_req_ack;
	assign cache_hits = r_cache_hits;
	assign cache_accesses = r_cache_accesses;
	reg [127:0] t_d0;
	wire [127:0] w_d0;
	wire [47:0] w_tag0;
	wire w_valid0;
	wire w_dirty0;
	reg_ram1rw #(
		.WIDTH(128),
		.LG_DEPTH(LG_L2_LINES)
	) data_ram0(
		.clk(clk),
		.addr(t_idx),
		.wr_data(t_d0),
		.wr_en(t_wr_d0),
		.rd_data(w_d0)
	);
	reg_ram1rw #(
		.WIDTH(TAG_BITS),
		.LG_DEPTH(LG_L2_LINES)
	) tag_ram0(
		.clk(clk),
		.addr(t_idx),
		.wr_data(r_tag),
		.wr_en(t_wr_tag),
		.rd_data(w_tag0)
	);
	reg_ram1rw #(
		.WIDTH(1),
		.LG_DEPTH(LG_L2_LINES)
	) valid_ram0(
		.clk(clk),
		.addr(t_idx),
		.wr_data(t_valid),
		.wr_en(t_wr_valid),
		.rd_data(w_valid0)
	);
	reg_ram1rw #(
		.WIDTH(1),
		.LG_DEPTH(LG_L2_LINES)
	) dirty_ram0(
		.clk(clk),
		.addr(t_idx),
		.wr_data(t_dirty),
		.wr_en(t_wr_dirty),
		.rd_data(w_dirty0)
	);
	wire w_hit = (w_valid0 ? r_tag == w_tag0 : 1'b0);
	wire w_need_wb = (w_valid0 ? w_dirty0 : 1'b0);
	reg n_mmu_mark_req;
	reg r_mmu_mark_req;
	reg n_mmu_mark_dirty;
	reg r_mmu_mark_dirty;
	reg n_mmu_mark_accessed;
	reg r_mmu_mark_accessed;
	reg r_mmu_req;
	reg n_mmu_req;
	reg r_l1d_req;
	reg n_l1d_req;
	reg r_l1i_req;
	reg n_l1i_req;
	reg r_last_gnt;
	reg n_last_gnt;
	reg n_req;
	reg r_req;
	reg r_mmu_addr3;
	reg n_mmu_addr3;
	reg n_mmu;
	reg r_mmu;
	reg n_mark_pte;
	reg r_mark_pte;
	always @(posedge clk)
		if (reset) begin
			r_mmu_addr3 <= 1'b0;
			r_mmu <= 1'b0;
			r_mark_pte <= 1'b0;
			r_mmu_rsp_data <= 'd0;
			r_mmu_rsp_valid <= 1'b0;
			r_mem_mark_rsp_valid <= 1'b0;
			r_state <= 5'd0;
			r_flush_state <= 1'd0;
			r_flush_complete <= 1'b0;
			r_idx <= 'd0;
			r_tag <= 'd0;
			r_opcode <= 4'd0;
			r_addr <= 'd0;
			r_saveaddr <= 'd0;
			r_mem_req <= 1'b0;
			r_mem_opcode <= 4'd0;
			r_rsp_data <= 'd0;
			r_l1d_rsp_valid <= 1'b0;
			r_l1i_rsp_valid <= 1'b0;
			r_reload <= 1'b0;
			r_req_ack <= 1'b0;
			r_store_data <= 'd0;
			r_flush_req <= 1'b0;
			r_need_l1d <= 1'b0;
			r_need_l1i <= 1'b0;
			r_cache_hits <= 'd0;
			r_cache_accesses <= 'd0;
			r_l1d_req <= 1'b0;
			r_l1i_req <= 1'b0;
			r_mmu_req <= 1'b0;
			r_mmu_mark_req <= 1'b0;
			r_last_gnt <= 1'b0;
			r_req <= 1'b0;
			r_last_l1i_addr <= 'd0;
			r_last_l1d_addr <= 'd0;
			r_mmu_mark_dirty <= 1'b0;
			r_mmu_mark_accessed <= 1'b0;
		end
		else begin
			r_mmu_addr3 <= n_mmu_addr3;
			r_mmu <= n_mmu;
			r_mark_pte <= n_mark_pte;
			r_mmu_rsp_data <= n_mmu_rsp_data;
			r_mmu_rsp_valid <= n_mmu_rsp_valid;
			r_mem_mark_rsp_valid <= n_mem_mark_rsp_valid;
			r_state <= n_state;
			r_flush_state <= n_flush_state;
			r_flush_complete <= n_flush_complete;
			r_idx <= t_idx;
			r_tag <= n_tag;
			r_opcode <= n_opcode;
			r_addr <= n_addr;
			r_saveaddr <= n_saveaddr;
			r_mem_req <= n_mem_req;
			r_mem_opcode <= n_mem_opcode;
			r_rsp_data <= n_rsp_data;
			r_l1d_rsp_valid <= n_l1d_rsp_valid;
			r_l1i_rsp_valid <= n_l1i_rsp_valid;
			r_reload <= n_reload;
			r_req_ack <= n_req_ack;
			r_store_data <= n_store_data;
			r_flush_req <= n_flush_req;
			r_need_l1i <= n_need_l1i;
			r_need_l1d <= n_need_l1d;
			r_cache_hits <= n_cache_hits;
			r_cache_accesses <= n_cache_accesses;
			r_l1d_req <= n_l1d_req;
			r_l1i_req <= n_l1i_req;
			r_mmu_req <= n_mmu_req;
			r_mmu_mark_req <= n_mmu_mark_req;
			r_last_gnt <= n_last_gnt;
			r_req <= n_req;
			r_last_l1i_addr <= n_last_l1i_addr;
			r_last_l1d_addr <= n_last_l1d_addr;
			r_mmu_mark_dirty <= n_mmu_mark_dirty;
			r_mmu_mark_accessed <= n_mmu_mark_accessed;
		end
	always @(posedge clk) r_mem_req_store_data <= n_mem_req_store_data;
	always @(*) begin
		if (_sv2v_0)
			;
		n_flush_state = r_flush_state;
		n_need_l1d = r_need_l1d | l1d_flush_req;
		n_need_l1i = r_need_l1i | l1i_flush_req;
		t_l2_flush_req = 1'b0;
		case (r_flush_state)
			1'd0:
				if (n_need_l1i | n_need_l1d)
					n_flush_state = 1'd1;
			1'd1: begin
				if (r_need_l1d && l1d_flush_complete)
					n_need_l1d = 1'b0;
				if (r_need_l1i && l1i_flush_complete)
					n_need_l1i = 1'b0;
				if ((n_need_l1d == 1'b0) && (n_need_l1i == 1'b0)) begin
					n_flush_state = 1'd0;
					t_l2_flush_req = 1'b1;
				end
			end
		endcase
	end
	reg t_probe_mmu_req_valid;
	reg [63:0] r_l2_probe_addr;
	reg [63:0] n_l2_probe_addr;
	reg n_l2_probe_val;
	reg r_l2_probe_val;
	assign l2_probe_val = r_l2_probe_val;
	assign l2_probe_addr = r_l2_probe_addr;
	reg [63:0] r_cycle;
	always @(posedge clk) r_cycle <= (reset ? 'd0 : r_cycle + 'd1);
	reg n_pstate;
	reg r_pstate;
	reg n_l2_probe_mmu;
	reg r_l2_probe_mmu;
	always @(*) begin
		if (_sv2v_0)
			;
		n_pstate = r_pstate;
		t_probe_mmu_req_valid = 1'b0;
		n_l2_probe_val = 1'b0;
		n_l2_probe_addr = r_l2_probe_addr;
		n_l2_probe_mmu = r_l2_probe_mmu;
		case (r_pstate)
			1'd0:
				if (mmu_req_valid) begin
					n_pstate = 1'd1;
					n_l2_probe_val = 1'b1;
					n_l2_probe_addr = mmu_req_addr;
					n_l2_probe_mmu = 1'b1;
				end
			1'd1:
				if (l2_probe_ack) begin
					n_pstate = 1'd0;
					t_probe_mmu_req_valid = r_l2_probe_mmu;
					n_l2_probe_mmu = 1'b0;
				end
			default:
				;
		endcase
	end
	always @(posedge clk)
		if (reset) begin
			r_pstate <= 1'd0;
			r_l2_probe_val <= 1'b0;
			r_l2_probe_addr <= 'd0;
			r_l2_probe_mmu <= 1'b0;
		end
		else begin
			r_pstate <= n_pstate;
			r_l2_probe_val <= n_l2_probe_val;
			r_l2_probe_addr <= n_l2_probe_addr;
			r_l2_probe_mmu <= n_l2_probe_mmu;
		end
	wire w_l1i_req = r_l1i_req | l1i_req;
	wire w_l1d_req = r_l1d_req | l1d_req;
	wire w_mmu_req = r_mmu_req | t_probe_mmu_req_valid;
	wire w_mem_mark_valid = mem_mark_valid | r_mmu_mark_req;
	always @(*) begin
		if (_sv2v_0)
			;
		n_last_gnt = r_last_gnt;
		n_l1i_req = r_l1i_req | l1i_req;
		n_l1d_req = r_l1d_req | l1d_req;
		n_mmu_req = r_mmu_req | t_probe_mmu_req_valid;
		n_mmu_mark_req = mem_mark_valid | r_mmu_mark_req;
		n_mem_mark_rsp_valid = 1'b0;
		n_req = r_req;
		n_mmu_rsp_data = r_mmu_rsp_data;
		n_mmu_rsp_valid = 1'b0;
		n_mmu_addr3 = r_mmu_addr3;
		n_mmu = r_mmu;
		n_mark_pte = r_mark_pte;
		n_state = r_state;
		n_flush_complete = 1'b0;
		t_wr_valid = 1'b0;
		t_wr_dirty = 1'b0;
		t_wr_tag = 1'b0;
		t_wr_d0 = 1'b0;
		t_idx = r_idx;
		n_tag = r_tag;
		n_opcode = r_opcode;
		n_addr = r_addr;
		n_saveaddr = r_saveaddr;
		n_req_ack = 1'b0;
		n_mem_req = r_mem_req;
		n_mem_opcode = r_mem_opcode;
		t_valid = 1'b0;
		t_dirty = 1'b0;
		t_d0 = mem_rsp_load_data[127:0];
		n_rsp_data = r_rsp_data;
		n_l1i_rsp_valid = 1'b0;
		n_l1d_rsp_valid = 1'b0;
		n_reload = r_reload;
		n_store_data = r_store_data;
		n_flush_req = r_flush_req | t_l2_flush_req;
		n_mem_req_store_data = r_mem_req_store_data;
		n_cache_hits = r_cache_hits;
		n_cache_accesses = r_cache_accesses;
		n_last_l1i_addr = r_last_l1i_addr;
		n_last_l1d_addr = r_last_l1d_addr;
		t_gnt_l1i = 1'b0;
		t_gnt_l1d = 1'b0;
		n_mmu_mark_dirty = r_mmu_mark_dirty;
		n_mmu_mark_accessed = r_mmu_mark_accessed;
		case (r_state)
			5'd0: begin
				t_valid = 1'b0;
				t_dirty = 1'b0;
				t_wr_valid = 1'b1;
				t_wr_dirty = 1'b1;
				t_wr_tag = 1'b1;
				t_wr_d0 = 1'b1;
				t_idx = r_idx + 'd1;
				if (r_idx == 4095) begin
					n_state = 5'd1;
					n_flush_complete = 1'b1;
				end
			end
			5'd1: begin
				t_idx = 'd0;
				n_tag = r_tag;
				n_addr = r_addr;
				n_opcode = 4'd4;
				n_store_data = r_store_data;
				if (n_flush_req) begin
					t_idx = 'd0;
					n_state = 5'd9;
				end
				else if (w_mem_mark_valid) begin
					n_mmu_mark_req = 1'b0;
					n_mmu_mark_dirty = mem_mark_dirty;
					n_mmu_mark_accessed = mem_mark_accessed;
					n_mmu_addr3 = mem_mark_addr[3];
					t_idx = mem_mark_addr[15:4];
					n_tag = mem_mark_addr[63:16];
					n_addr = {mem_mark_addr[63:4], {4 {1'b0}}};
					n_saveaddr = {mem_mark_addr[63:4], {4 {1'b0}}};
					n_opcode = 4'd4;
					n_mark_pte = 1'b1;
					n_state = 5'd2;
				end
				else if (w_mmu_req) begin
					n_mmu_addr3 = mmu_req_addr[3];
					t_idx = mmu_req_addr[15:4];
					n_tag = mmu_req_addr[63:16];
					n_addr = {mmu_req_addr[63:4], {4 {1'b0}}};
					n_saveaddr = {mmu_req_addr[63:4], {4 {1'b0}}};
					n_opcode = 4'd4;
					n_state = 5'd2;
					n_mmu = 1'b1;
				end
				else if (w_l1d_req | w_l1i_req) begin
					if (w_l1i_req & !w_l1d_req) begin
						n_last_gnt = 1'b0;
						t_idx = l1i_addr[15:4];
						n_tag = l1i_addr[63:16];
						n_last_l1i_addr = l1i_addr[63:4];
						n_addr = {l1i_addr[63:4], {4 {1'b0}}};
						n_saveaddr = {l1i_addr[63:4], {4 {1'b0}}};
						n_opcode = 4'd4;
						n_l1i_req = 1'b0;
						t_gnt_l1i = 1'b1;
					end
					else if (!w_l1i_req & w_l1d_req) begin
						n_last_gnt = 1'b1;
						t_idx = l1d_addr[15:4];
						n_tag = l1d_addr[63:16];
						n_addr = {l1d_addr[63:4], {4 {1'b0}}};
						n_last_l1d_addr = l1d_addr[63:4];
						n_saveaddr = {l1d_addr[63:4], {4 {1'b0}}};
						n_store_data = l1_mem_req_store_data;
						n_opcode = l1d_opcode;
						n_l1d_req = 1'b0;
						if (!((l1d_opcode == 4'd7) || (l1d_opcode == 4'd4))) begin
							$display("opcode is %d", l1d_opcode);
							$stop;
						end
						if (l1d_opcode == 4'd7)
							n_l1d_rsp_valid = 1'b1;
						t_gnt_l1d = 1'b1;
					end
					else if (r_last_gnt) begin
						n_last_gnt = 1'b0;
						t_idx = l1i_addr[15:4];
						n_tag = l1i_addr[63:16];
						n_last_l1i_addr = l1i_addr[63:4];
						n_addr = {l1i_addr[63:4], {4 {1'b0}}};
						n_saveaddr = {l1i_addr[63:4], {4 {1'b0}}};
						n_opcode = 4'd4;
						n_l1i_req = 1'b0;
						t_gnt_l1i = 1'b1;
					end
					else begin
						n_last_gnt = 1'b1;
						t_idx = l1d_addr[15:4];
						n_tag = l1d_addr[63:16];
						n_addr = {l1d_addr[63:4], {4 {1'b0}}};
						n_last_l1d_addr = l1d_addr[63:4];
						n_saveaddr = {l1d_addr[63:4], {4 {1'b0}}};
						n_store_data = l1_mem_req_store_data;
						n_opcode = l1d_opcode;
						n_l1d_req = 1'b0;
						if (!((l1d_opcode == 4'd7) || (l1d_opcode == 4'd4)))
							$stop;
						if (l1d_opcode == 4'd7)
							n_l1d_rsp_valid = 1'b1;
						t_gnt_l1d = 1'b1;
					end
					n_req_ack = 1'b1;
					n_state = 5'd2;
					n_cache_accesses = r_cache_accesses + 64'd1;
					n_cache_hits = r_cache_hits + 64'd1;
				end
			end
			5'd2:
				if (w_hit) begin
					n_reload = 1'b0;
					if (r_opcode == 4'd4) begin
						n_rsp_data = w_d0;
						if (r_mmu) begin
							n_mmu_rsp_data = (r_mmu_addr3 ? w_d0[127:64] : w_d0[63:0]);
							n_mmu_rsp_valid = 1'b1;
							n_mmu_req = 1'b0;
							n_mmu = 1'b0;
							n_state = 5'd1;
						end
						else if (r_mark_pte) begin
							n_state = 5'd7;
							n_mmu_mark_dirty = 1'b0;
							n_mmu_mark_accessed = 1'b0;
							t_d0 = (r_mmu_addr3 ? {w_d0[127:72], r_mmu_mark_dirty | w_d0[71], r_mmu_mark_accessed | w_d0[70], w_d0[69:0]} : {w_d0[127:8], r_mmu_mark_dirty | w_d0[7], r_mmu_mark_accessed | w_d0[6], w_d0[5:0]});
							t_wr_dirty = 1'b1;
							t_dirty = 1'b1;
							t_wr_d0 = 1'b1;
							n_mark_pte = 1'b0;
							n_mem_mark_rsp_valid = 1'b1;
						end
						else if (r_last_gnt == 1'b0) begin
							n_l1i_rsp_valid = 1'b1;
							n_state = 5'd1;
						end
						else begin
							n_l1d_rsp_valid = 1'b1;
							n_state = 5'd1;
						end
					end
					else if (r_opcode == 4'd7) begin
						t_wr_dirty = 1'b1;
						t_dirty = 1'b1;
						n_state = 5'd7;
						t_d0 = r_store_data;
						t_wr_d0 = 1'b1;
					end
				end
				else begin
					n_cache_hits = r_cache_hits - 64'd1;
					if (w_dirty0) begin
						n_mem_req_store_data = w_d0;
						n_addr = {w_tag0, t_idx, {4 {1'b0}}};
						n_mem_opcode = 4'd7;
						n_mem_req = 1'b1;
						n_state = 5'd4;
					end
					else begin
						if (r_reload)
							$stop;
						n_reload = 1'b1;
						n_state = 5'd3;
						n_mem_opcode = 4'd4;
						n_mem_req = 1'b1;
					end
				end
			5'd4:
				if (mem_rsp_valid) begin
					n_addr = r_saveaddr;
					n_mem_opcode = 4'd4;
					n_state = 5'd5;
					n_mem_req = 1'b0;
				end
			5'd5: begin
				n_state = 5'd3;
				n_reload = 1'b1;
				n_mem_req = 1'b1;
			end
			5'd3:
				if (mem_rsp_valid) begin
					n_mem_req = 1'b0;
					t_valid = 1'b1;
					t_wr_valid = 1'b1;
					t_wr_tag = 1'b1;
					t_wr_d0 = 1'b1;
					n_state = 5'd6;
				end
			5'd6: n_state = 5'd2;
			5'd7: n_state = 5'd1;
			5'd9: begin
				n_state = 5'd10;
				t_valid = 1'b0;
				t_dirty = 1'b0;
				t_wr_valid = 1'b1;
				t_wr_dirty = 1'b1;
			end
			5'd10:
				if (w_need_wb) begin
					n_mem_req_store_data = w_d0;
					n_addr = {w_tag0, t_idx, {4 {1'b0}}};
					n_mem_opcode = 4'd7;
					n_mem_req = 1'b1;
					n_state = 5'd8;
				end
				else begin
					t_idx = r_idx + 'd1;
					if (r_idx == 4095) begin
						n_state = 5'd1;
						n_flush_complete = 1'b1;
						n_flush_req = 1'b0;
					end
					else
						n_state = 5'd9;
				end
			5'd8:
				if (mem_rsp_valid) begin
					n_mem_req = 1'b0;
					t_idx = r_idx + 'd1;
					if (r_idx == 4095) begin
						n_state = 5'd1;
						n_flush_complete = 1'b1;
						n_flush_req = 1'b0;
					end
					else
						n_state = 5'd9;
				end
			default:
				;
		endcase
	end
	initial _sv2v_0 = 0;
endmodule

