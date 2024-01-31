<template>
  <div class="app-container">
    <el-form :model="queryParams" ref="queryForm" size="small" :inline="true" v-show="showSearch">
      <el-form-item label="扫描进程名称" prop="deptName">
        <el-input
          v-model="queryParams.deptName"
          placeholder="请输入扫描进程名称"
          clearable
          @keyup.enter.native="handleQuery"
        />
      </el-form-item>
      <el-form-item label="状态" prop="status">
        <el-select v-model="queryParams.status" placeholder="扫描状态" clearable>
          <el-option
            v-for="dict in dict.type.sys_normal_disable"
            :key="dict.value"
            :label="dict.label"
            :value="dict.value"
          />
        </el-select>
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
          @click="handleAdd"
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

    <el-table v-loading="loading" :data="scanList" @selection-change="handleSelectionChange">
    <!-- <el-table
      v-if="refreshTable"
      v-loading="loading"
      :data="scanList"
      row-key="scanId"
      :default-expand-all="isExpandAll"
      :tree-props="{children: 'children', hasChildren: 'hasChildren'}"
    > -->
      <el-table-column prop="name" label="扫描名称" width="100"></el-table-column>

      <el-table-column label="开始时间" align="center" prop="startTime" width="230">
        <!-- <template slot-scope="scope">
          <span>{{ parseTime(scope.row.startTime) }}</span>
        </template> -->
      </el-table-column>

      <el-table-column prop="scan_time" label="运行时间(秒)" width="80"></el-table-column>

      <el-table-column label="结束时间" align="center" prop="endTime" width="230">
        <!-- <template slot-scope="scope">
          <span>{{ parseTime(scope.row.endTime) }}</span>
        </template> -->
      </el-table-column>

      <el-table-column prop="status" label="扫描状态" width="100">
        <!-- <template slot-scope="scope">
          <dict-tag :options="dict.type.sys_normal_disable" :value="scope.row.status"/>
        </template> -->
      </el-table-column>

      <el-table-column prop="scanned_domains" label="扫描域名数" width="100"></el-table-column>
      <el-table-column prop="successes" label="获取成功" width="100"></el-table-column>
      <el-table-column prop="errors" label="获取失败" width="100"></el-table-column>
      <el-table-column prop="scanned_certs" label="获取证书数量" width="100"></el-table-column>

    </el-table>

  </div>
</template>

<script>
import { listScanProcess, addScanProcess } from "@/api/system/scan_process";
import Treeselect from "@riophae/vue-treeselect";
import "@riophae/vue-treeselect/dist/vue-treeselect.css";

export default {
  name: "Scan Process",
  dicts: ['sys_normal_disable'],
  components: { Treeselect },
  data() {
    return {
      // 遮罩层
      loading: true,
      // 显示搜索条件
      showSearch: true,
      // 表格树数据
      scanList: [],
      // 部门树选项
      deptOptions: [],
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
        deptName: undefined,
        status: undefined
      },
      // 表单参数
      form: {},
      // 表单校验
      rules: {
        parentId: [
          { required: true, message: "上级部门不能为空", trigger: "blur" }
        ],
        deptName: [
          { required: true, message: "部门名称不能为空", trigger: "blur" }
        ],
        orderNum: [
          { required: true, message: "显示排序不能为空", trigger: "blur" }
        ],
        email: [
          {
            type: "email",
            message: "请输入正确的邮箱地址",
            trigger: ["blur", "change"]
          }
        ],
        phone: [
          {
            pattern: /^1[3|4|5|6|7|8|9][0-9]\d{8}$/,
            message: "请输入正确的手机号码",
            trigger: "blur"
          }
        ]
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
    /** 查询部门列表 */
    getList() {
      this.loading = true;
      listScanProcess(this.queryParams).then(response => {
        // this.scanList = this.handleTree(response.data, "scanId");
        this.scanList = response.data;
        this.loading = false;
      });
    },
    /** 新增按钮操作 */
    handleAdd(row) {
      // this.reset();
      // if (row != undefined) {
      //   this.form.parentId = row.scanId;
      // }
      // this.open = true;
      // this.title = "新增";
      addScanProcess().then(response => {
        // this.deptOptions = this.handleTree(response.data, "scanId");
        this.getList();
      });
    },
    /** 定时刷新表格数据 */
    startAutoRefresh() {
      this.autoRefreshTimer = setInterval(() => {
        this.getList();
      }, 5000);
    },
    stopAutoRefresh() {
      // 停止定时器的逻辑
      clearInterval(this.autoRefreshTimer);
    },
  },
};
</script>
