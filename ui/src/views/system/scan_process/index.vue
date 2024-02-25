<template>
  <div class="app-container">
    <el-form :model="queryParams" ref="queryForm" size="small" :inline="true" v-show="showSearch">
      <el-form-item label="扫描进程名称" prop="scanProcessName">
        <el-input
          v-model="queryParams.scanProcessName"
          placeholder="请输入扫描进程名称"
          clearable
          @keyup.enter.native="handleQuery"
        />
      </el-form-item>

      <el-form-item label="扫描状态" prop="scanStatus">
        <el-select v-model="queryParams.scanStatus" placeholder="扫描状态" clearable>
          <el-option
            v-for="dict in dict.type.sys_scan_status"
            :key="dict.value"
            :label="dict.label"
            :value="dict.value"
          />
        </el-select>
      </el-form-item>

      <el-form-item label="扫描日期范围" prop="scanDateRange">
        <el-date-picker
          v-model="scanDateRange"
          style="width: 240px"
          value-format="yyyy-MM-dd"
          type="daterange"
          range-separator="-"
          start-placeholder="开始日期"
          end-placeholder="结束日期"
        ></el-date-picker>
      </el-form-item>

      <el-form-item>
        <el-button type="primary" icon="el-icon-search" size="mini" @click="handleQuery">搜索</el-button>
        <el-button icon="el-icon-refresh" size="mini" @click="resetQuery">重置</el-button>
      </el-form-item>
    </el-form>

    <el-row :gutter="10" class="mb8">
      <el-col :span="1.5">
        <el-button
          type="primary"
          plain
          icon="el-icon-plus"
          size="mini"
          @click="addScan"
          v-hasPermi="['system:scan_process:add']"
        >新增进程</el-button>
      </el-col>
      <el-col :span="1.5">
        <el-button
          type="info"
          plain
          icon="el-icon-sort"
          size="mini"
          @click="toggleExpandAll"
        >展开/折叠</el-button>
      </el-col>
      <right-toolbar :showSearch.sync="showSearch" @queryTable="getList"></right-toolbar>
    </el-row>

    <el-table
      v-if="refreshTable"
      v-loading="loading"
      :data="scanList"
      row-key="scanId"
      :default-expand-all="isExpandAll"
      :tree-props="{children: 'children', hasChildren: 'hasChildren'}"
      >
      <el-table-column prop="id" label="扫描ID" width="200"></el-table-column>
      <el-table-column prop="name" label="扫描名称" width="100"></el-table-column>

      <el-table-column prop="num_threads" label="线程数量" align="center" width="100"></el-table-column>
      <el-table-column prop="scanType" label="扫描类型" align="center" width="100">
        <template slot-scope="scope">
          <dict-tag :options="dict.type.sys_scan_type" :value="scope.row.scanType"/>
        </template>
      </el-table-column>

      <el-table-column prop="startTime" label="开始时间" align="center" width="230">
        <!-- <template slot-scope="scope">
          <span>{{ parseTime(scope.row.startTime) }}</span>
        </template> -->
      </el-table-column>

      <el-table-column prop="scan_time_in_seconds" label="运行时间(秒)" align="center" width="80"></el-table-column>
      <el-table-column label="结束时间" align="center" prop="endTime" width="230">
        <!-- <template slot-scope="scope">
          <span>{{ parseTime(scope.row.endTime) }}</span>
        </template> -->
      </el-table-column>

      <el-table-column prop="status" label="扫描状态" align="center" width="100">
        <template slot-scope="scope">
          <dict-tag :options="dict.type.sys_scan_status" :value="scope.row.status"/>
        </template>
      </el-table-column>

      <el-table-column prop="scanned_domains" label="扫描域名数" align="center" width="100"></el-table-column>
      <el-table-column prop="successes" label="获取成功" align="center" width="100"></el-table-column>
      <el-table-column prop="errors" label="获取失败" align="center" width="100"></el-table-column>
      <el-table-column prop="scanned_certs" label="获取证书数量" align="center" width="100"></el-table-column>

      <el-table-column label="操作" align="center" class-name="small-padding fixed-width">
        <template slot-scope="scope">
          <el-button
            size="mini"
            type="text"
            icon="el-icon-close"
            @click="stopScan(scope.row)"
            v-hasPermi="['system:scan_process:stop']"
          >终止进程</el-button>

          <el-button
            size="mini"
            type="text"
            icon="el-icon-edit"
            @click="editScan(scope.row)"
            v-hasPermi="['system:scan_process:edit']"
          >修改进程参数</el-button>

          <el-button
            size="mini"
            type="text"
            icon="el-icon-search"
            @click="viewResult(scope.row)"
            v-hasPermi="['system:scan_process:view']"
          >查看扫描结果</el-button>

          <el-button
            size="mini"
            type="text"
            icon="el-icon-delete"
            @click="deleteScan(scope.row)"
            v-hasPermi="['system:scan_process:remove']"
          >删除进程</el-button>
        </template>
      </el-table-column>

    </el-table>

    <pagination
      v-show="total>0"
      :total="total"
      :page.sync="queryParams.pageNum"
      :limit.sync="queryParams.pageSize"
      @pagination="getList"
    />

    <!-- Config for new scan process -->
    <el-dialog :title="title" :visible.sync="open" width="600px" append-to-body>
      <el-form ref="form" :model="form" :rules="rules" label-width="130px">
        <el-row>
          <el-col :span="50">
            <el-form-item label="扫描进程名称" prop="scanName">
              <el-input v-model="form.scanName" placeholder="请输入扫描进程名称" :maxlength="20" />
            </el-form-item>
          </el-col>
        </el-row>

        <el-row>
          <el-col :span="50">
            <el-form-item label="扫描方式" prop="scanTypeOptions">
                <el-select v-model="form.scanTypeOptions" @change="handleScanTypeOptionChange" placeholder="选择扫描方式">
                  <el-option
                    v-for="dict in dict.type.sys_scan_type"
                    :key="dict.value"
                    :label="dict.label"
                    :value="dict.value"
                  />
                </el-select>
            </el-form-item>
          </el-col>
        </el-row>

        <el-row>
          <el-col :span="50">
            <el-form-item label="扫描域名数量" prop="scanDomainNum">
              <!-- <el-input v-model="form.scanDomainNum" placeholder="请输入要扫描的域名数量" /> -->
              <el-input-number v-model="form.scanDomainNum" controls-position="right" :min="1" :max="10000000"/>
            </el-form-item>
          </el-col>
        </el-row>

        <el-row>
          <el-col :span="50">
            <el-form-item label="扫描线程数量" prop="scanThreadNum">
              <el-input-number v-model="form.scanThreadNum" controls-position="right" :min="1" :max="100"/>
            </el-form-item>
          </el-col>
        </el-row>

      </el-form>
      <div slot="footer" class="dialog-footer">
        <el-button type="primary" @click="submitForm">确 定</el-button>
        <el-button @click="cancel">取 消</el-button>
      </div>
    </el-dialog>

  </div>
</template>

<script>
import { listScanProcess, addScanProcess } from "@/api/system/scan_process";
import Treeselect from "@riophae/vue-treeselect";
import "@riophae/vue-treeselect/dist/vue-treeselect.css";

export default {
  name: "ScanProcess",
  dicts: ['sys_scan_type', 'sys_scan_status'],
  components: { Treeselect },
  data() {
    return {
      // 遮罩层
      loading: true,
      // 显示搜索条件
      showSearch: true,
      // 表格树数据
      scanList: [],
      // 弹出层标题
      title: "",
      // 是否显示弹出层
      open: false,
      // 是否展开，默认全部展开
      isExpandAll: true,
      // 重新渲染表格状态
      refreshTable: true,
      // 查询参数
      queryParams: {
        pageNum: 1,
        pageSize: 10,
        scanProcessName: undefined,
        scanStatus: undefined
      },
      // 扫描起止时间
      scanDateRange : [],
      // 表单参数
      form: {},
      // 表单校验
      rules: {
        scanName: [
          { required: true, message: "扫描名称不能为空", trigger: "blur" }
        ],
        scanTypeOptions: [
          { required: true, message: "扫描方式不能为空", trigger: "blur" }
        ],
        scanDomainNum: [
          { required: true, message: "扫描域名数量不能为空", trigger: "blur" }
        ],
        scanThreadNum: [
          { required: true, message: "扫描线程分配数量不能为空", trigger: "blur" }
        ],
      }
    };
  },
  created() {
    this.getList();
    this.startAutoRefresh();
  },
  beforeDestroy() {
    this.stopAutoRefresh();
  },
  methods: {
    /** 定时刷新表格数据 */
    startAutoRefresh() {
      this.autoRefreshTimer = setInterval(() => {
        this.getList();
      }, 15000);
    },
    stopAutoRefresh() {
      // 停止定时器的逻辑
      clearInterval(this.autoRefreshTimer);
    },
    /** 搜索按钮操作 */
    handleQuery() {
      this.queryParams.pageNum = 1;
      this.getList();
    },
    /** 重置按钮操作 */
    resetQuery() {
      this.resetForm("queryForm");
      this.handleQuery();
    },
    /** 查询扫描进程列表 */
    getList() {
      this.loading = true;
      listScanProcess(this.addDateRange(this.queryParams, this.scanDateRange)).then(response => {
        this.scanList = response.data;
        this.loading = false;
      });
    },
    /** 新增按钮操作 */
    addScan(row) {
      this.reset();
      if (row != undefined) {
        this.form.parentId = row.scanId;
      }
      this.open = true;
      this.title = "新增扫描进程";
    },
    /** 展开/折叠操作 */
    toggleExpandAll() {
      this.refreshTable = false;
      this.isExpandAll = !this.isExpandAll;
      this.$nextTick(() => {
        this.refreshTable = true;
      });
    },
    handleScanTypeOptionChange() {
      console.log("用户选择的扫描方式：", this.form.scanTypeOptions);
    },
    /** 提交按钮 */
    submitForm: function() {
      this.$refs["form"].validate(valid => {
        if (valid) {
          if (this.form.scanId != undefined) {
            updateScanProcess(this.form).then(response => {
              this.$modal.msgSuccess("修改成功");
              this.open = false;
              this.getList();
            });
          } else {
            addScanProcess(this.form).then(response => {
              this.$modal.msgSuccess("新增成功");
              this.open = false;
              this.getList();
            });
          }
        }
      });
    },
    // 取消按钮
    cancel() {
      this.open = false;
      this.reset();
    },
    // 表单重置
    reset() {
      this.form = {
        scanName: undefined,
        scanTypeOptions: undefined,
        scanDomainNum: undefined,
        scanThreadNum: undefined
      };
      this.resetForm("form");
    },
  },
};
</script>
