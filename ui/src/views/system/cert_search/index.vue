<template>
  <div class="app-container">
    <el-form :model="queryParams" ref="queryForm" size="small" :inline="true" v-show="showSearch">
      <el-form-item label="证书SHA256" prop="certID">
        <el-input
          v-model="queryParams.certID"
          placeholder="请输入证书SHA256"
          clearable
          @keyup.enter.native="handleQuery"
        />
      </el-form-item>

      <el-form-item label="域名" prop="certDomain">
        <el-input
          v-model="queryParams.certDomain"
          placeholder="请输入证书对应域名"
          clearable
          @keyup.enter.native="handleQuery"
        />
      </el-form-item>
      
      <el-form-item label="扫描日期" prop="scanDate">
        <el-date-picker
          v-model="queryParams.scanDate"
          type="date"
          placeholder="请选择证书扫描日期"
          format="yyyy-MM-dd"
          value-format="yyyy-MM-dd"
        ></el-date-picker>
      </el-form-item>

      <el-form-item>
        <el-button type="primary" icon="el-icon-search" size="mini" @click="handleQuery">搜索</el-button>
        <el-button icon="el-icon-refresh" size="mini" @click="resetQuery">重置</el-button>
      </el-form-item>
    </el-form>

    <el-table
      v-if="refreshTable"
      v-loading="loading"
      :data="searchResult"
      row-key="scanId"
      :default-expand-all="isExpandAll"
      :tree-props="{children: 'children', hasChildren: 'hasChildren'}"
      >

      crt.sh ID	 Logged At  ⇧	Not Before	Not After	Common Name	Matching Identities	Issuer Name
      'cert_id': self.CERT_ID,
            'cert_type': self.CERT_TYPE,
            'issuer_org': self.ISSUER_ORG,
            'issuer_cert_id': self.ISSUER_CERT_ID,
            'key_size': self.KEY_SIZE,
            'key_type': self.KEY_TYPE,
            'not_valid_before': self.NOT_VALID_BEFORE,
            'not_valid_after': self.NOT_VALID_AFTER,
            'validation_period': self.VALIDATION_PERIOD,
            'expired': self.EXPIRED
        }

      <el-table-column prop="cert_id" label="证书ID" width="200">
        <template slot-scope="scope">
          <router-link :to="'/system/cert_search/index/' + scope.row.cert_id" class="link-type">
            <span>{{ scope.row.dictType }}</span>
          </router-link>
        </template>
      </el-table-column>

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


    </el-table>

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
      searchResult: [],
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
        certID: undefined,
        certDomain: undefined,
        scanDate: undefined
      }
    };
  },

  methods: {
    /** 搜索按钮操作 */
    handleQuery() {
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
      listScanProcess(this.queryParams).then(response => {
        // this.searchResult = this.handleTree(response.data, "scanId");
        this.searchResult = response.data;
        this.loading = false;
      });
    },
    /** 展开/折叠操作 */
    toggleExpandAll() {
      this.refreshTable = false;
      this.isExpandAll = !this.isExpandAll;
      this.$nextTick(() => {
        this.refreshTable = true;
      });
    },
  },
};
</script>
