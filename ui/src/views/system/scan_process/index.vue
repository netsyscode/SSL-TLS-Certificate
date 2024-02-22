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

    <el-table
      v-if="refreshTable"
      v-loading="loading"
      :data="scanList"
      row-key="scanId"
      :default-expand-all="isExpandAll"
      >
      <!-- :tree-props="{children: 'children', hasChildren: 'hasChildren'}" -->
      <el-table-column prop="name" label="扫描名称" width="100"></el-table-column>

      <el-table-column label="开始时间" align="center" prop="startTime" width="230">
        <!-- <template slot-scope="scope">
          <span>{{ parseTime(scope.row.startTime) }}</span>
        </template> -->
      </el-table-column>

      <el-table-column prop="scan_time" label="运行时间(秒)" align="center" width="80"></el-table-column>

      <el-table-column label="结束时间" align="center" prop="endTime" width="230">
        <!-- <template slot-scope="scope">
          <span>{{ parseTime(scope.row.endTime) }}</span>
        </template> -->
      </el-table-column>

      <el-table-column prop="status" label="扫描状态" align="center" width="100">
        <!-- <template slot-scope="scope">
          <dict-tag :options="dict.type.sys_normal_disable" :value="scope.row.status"/>
        </template> -->
      </el-table-column>

      <el-table-column prop="scanned_domains" label="扫描域名数" align="center" width="100"></el-table-column>
      <el-table-column prop="successes" label="获取成功" align="center" width="100"></el-table-column>
      <el-table-column prop="errors" label="获取失败" align="center" width="100"></el-table-column>
      <el-table-column prop="scanned_certs" label="获取证书数量" align="center" width="100"></el-table-column>

    </el-table>

    <!-- Config for new scan process -->
    <el-dialog :title="title" :visible.sync="open" width="600px" append-to-body>
      <el-form ref="form" :model="form" :rules="rules" label-width="80px">
        <el-row>
          <el-col :span="24" v-if="form.parentId !== 0">

            <el-form-item label="扫描方式" prop="scanTypeOptions">
              <el-select v-model="form.scanTypeOptions" @change="handleScanTypeOptionChange" placeholder="选择扫描方式">
                <el-option label="扫描Top域名" value="0"></el-option>
                <el-option label="扫描IP地址" value="1"></el-option>
                <el-option label="扫描CT日志" value="2"></el-option>
              </el-select>
            </el-form-item>

            <!-- <el-form-item label="扫描方式" prop="parentId">
              <treeselect v-model="form.parentId" :options="scanTypeOptions" :normalizer="normalizer" placeholder="选择上级部门" />
            </el-form-item> -->
          </el-col>
        </el-row>

        <el-row>
          <el-col :span="50">
            <el-form-item label-width="130px" label="扫描域名数量" prop="scanDomainNum">
              <!-- <el-input v-model="form.scanDomainNum" placeholder="请输入要扫描的域名数量" /> -->
              <el-input-number v-model="form.scanDomainNum" controls-position="right" :min="1" :max="10000000"/>
            </el-form-item>
          </el-col>
        </el-row>

        <el-row>
          <el-col :span="50">
            <el-form-item label-width="150px" label="扫描线程分配数量" prop="scanThreadNum">
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
      scanTypeOptions: [],
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
    // this.startAutoRefresh();
  },
  beforeDestroy() {
    // this.stopAutoRefresh();
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
      this.reset();
      if (row != undefined) {
        this.form.parentId = row.scanId;
      }
      this.open = true;
      this.title = "新增扫描进程";
      // getList().then(response => {
      //   this.scanTypeOptions = this.handleTree(response.data, "scanId");
      // });
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

    /** 转换菜单数据结构 */
    normalizer(node) {
      if (node.children && !node.children.length) {
        delete node.children;
      }
      return {
        id: node.menuId,
        label: node.menuName,
        children: node.children
      };
    },
    /** 提交按钮 */
    submitForm: function() {
      this.$refs["form"].validate(valid => {
        if (valid) {
          if (this.form.deptId != undefined) {
            updateDept(this.form).then(response => {
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
        scanTypeOptions: undefined,
        scanDomainNum: undefined,
        scanThreadNum: undefined
      };
      this.resetForm("form");
    },
    handleScanTypeOptionChange() {
      console.log("用户选择的扫描方式：", this.form.scanTypeOptions);

      // 在这里你可以根据选择执行相应的逻辑
      // 例如，发起请求、更新相关数据等
    },
    /** 展开/折叠操作 */
    toggleExpandAll() {
      this.refreshTable = false;
      this.isExpandAll = !this.isExpandAll;
      this.$nextTick(() => {
        this.refreshTable = true;
      });
    },
    /** 搜索按钮操作 */
    handleQuery() {
      this.getList();
    },
    /** 重置按钮操作 */
    resetQuery() {
      this.resetForm("queryForm");
      this.handleQuery();
    },

  },
};
</script>
