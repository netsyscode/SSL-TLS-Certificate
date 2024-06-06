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

      <el-form-item label="证书域名" prop="certDomain">
        <el-input
          v-model="queryParams.certDomain"
          placeholder="请输入证书对应域名"
          clearable
          @keyup.enter.native="handleQuery"
        />
      </el-form-item>
      
      <el-form-item label="有效起始日期范围" prop="notValidBeforeRange">
        <el-date-picker
          v-model="notValidBeforeRange"
          style="width: 240px"
          value-format="yyyy-MM-dd"
          type="daterange"
          range-separator="-"
          start-placeholder="开始日期"
          end-placeholder="结束日期"
        ></el-date-picker>
      </el-form-item>

      <el-form-item label="有效终止日期范围" prop="notValidAfterRange">
        <el-date-picker
          v-model="notValidAfterRange"
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

    <el-table
      v-if="refreshTable"
      v-loading="loading"
      :data="searchResult"
      row-key="certId"
      :default-expand-all="isExpandAll"
      :tree-props="{children: 'children', hasChildren: 'hasChildren'}"
      >

      <el-table-column prop="cert_id" label="证书ID" width="200">
        <template slot-scope="scope">
          <router-link :to="'/system/cert_view/' + scope.row.cert_id" class="link-type">
            <span>{{ scope.row.cert_id }}</span>
          </router-link>
        </template>
      </el-table-column>

      <el-table-column prop="cert_type" label="证书类别" align="center" width="100">
        <template slot-scope="scope">
          <dict-tag :options="dict.type.sys_cert_type" :value="scope.row.cert_type"/>
        </template>
      </el-table-column>

      <el-table-column prop="subject_cn" label="主体域名" align="center" width="300"></el-table-column>
      <el-table-column prop="issuer_org" label="签发者" align="center" width="300"></el-table-column>
      <el-table-column prop="validation_period" label="有效期(天)" align="center" width="100"></el-table-column>

      <el-table-column prop="not_valid_before_utc" label="有效期开始时间" align="center" width="230">
        <!-- <template slot-scope="scope">
          <span>{{ parseTime(scope.row.startTime) }}</span>
        </template> -->
      </el-table-column>
      <el-table-column prop="not_valid_after_utc" label="有效期截止时间" align="center" width="230">
        <!-- <template slot-scope="scope">
          <span>{{ parseTime(scope.row.startTime) }}</span>
        </template> -->
      </el-table-column>
      
    </el-table>

    <pagination
      v-show="total>0"
      :total="total"
      :page.sync="queryParams.pageNum"
      :limit.sync="queryParams.pageSize"
      @pagination="getList"
    />

  </div>
</template>

<script>
import { listCert } from "@/api/system/cert_search";
import Treeselect from "@riophae/vue-treeselect";
import "@riophae/vue-treeselect/dist/vue-treeselect.css";

export default {
  name: "CertSearch",
  dicts: ['sys_cert_type'],
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
        pageNum: 1,
        pageSize: 30,
        certID: undefined,
        certDomain: undefined
      },
      notValidBeforeRange: [],
      notValidAfterRange: [],
      // 总条数
      total: 0
    };
  },
  created() {
    this.loading = false;
  },
  methods: {
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
      let queryParams = this.addDateRange(this.queryParams, this.notValidBeforeRange, "NotValidBefore")
      let finalQueryParams = this.addDateRange(queryParams, this.notValidAfterRange, "NotValidAfter")
      console.log(finalQueryParams)

      listCert(finalQueryParams).then(response => {
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
