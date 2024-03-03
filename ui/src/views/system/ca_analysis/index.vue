<template>
  <div class="app-container">
    <el-form :model="queryParams" ref="queryForm" size="small" :inline="true" v-show="showSearch">
      <el-form-item label="扫描结果名称" prop="deptName">
        <el-input
          v-model="queryParams.deptName"
          placeholder="请输入扫描结果名称"
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
          v-hasPermi="['system:cert:add']"
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

    <el-table v-loading="loading" :data="certResultList" @selection-change="handleSelectionChange">
    <!-- <el-table
      v-if="refreshTable"
      v-loading="loading"
      :data="scanList"
      row-key="scanId"
      :default-expand-all="isExpandAll"
      :tree-props="{children: 'children', hasChildren: 'hasChildren'}"
      > -->
      <el-table-column prop="scan_id" label="扫描ID" width="100"></el-table-column>
      <el-table-column prop="scanned_cert_num" label="扫描证书数量(去重后)" width="100"></el-table-column>
      <el-table-column prop="expired_percent" label="证书过期比例" width="100"></el-table-column>

      <el-table-column prop="chartDataList" label="图表" width="1000">
        
        <template slot-scope="{ row }">
          <div>
            <multi-e-charts-pie-chart :chartDataList="row.chartDataList"></multi-e-charts-pie-chart>
          </div>
        </template>
        
      </el-table-column>

      <!-- <el-table-column prop="issuer_count" label="证书签发者统计" width="500">
        <div>
          <e-charts-pie-chart :chartData="myChartData" :chartOptions="myChartOptions"></e-charts-pie-chart>
        </div>
      </el-table-column>

      <el-table-column prop="key_type_count" label="证书密钥类型统计" width="500">
        <div>
          <e-charts-pie-chart :chartData="myChartData" :chartOptions="myChartOptions"></e-charts-pie-chart>
        </div>
      </el-table-column>
      <el-table-column prop="key_size_count" label="证书密钥长度统计" width="500">
        <div>
          <e-charts-pie-chart :chartData="myChartData" :chartOptions="myChartOptions"></e-charts-pie-chart>
        </div>
      </el-table-column>
      <el-table-column prop="validation_period_count" label="证书有效时长统计" width="500">
        <div>
          <e-charts-pie-chart :chartData="myChartData" :chartOptions="myChartOptions"></e-charts-pie-chart>
        </div>
      </el-table-column> -->
      
    </el-table>

  </div>
</template>

<script>
import { listCertAnalysisResult } from "@/api/system/cert_analysis";
import Treeselect from "@riophae/vue-treeselect";
import "@riophae/vue-treeselect/dist/vue-treeselect.css";
import MultiEChartsPieChart from '../components/piechart/MultiPieChart';

export default {
  name: "Cert Analysis",
  dicts: ['sys_normal_disable'],
  components: { Treeselect, MultiEChartsPieChart },

  data() {
    return {
      // 遮罩层
      loading: true,
      // 显示搜索条件
      showSearch: true,
      // 表格树数据
      certResultList: [],
      // return {
      //       'scan_id': self.SCAN_ID,
      //       # 'scan_created_datetime': self.SCANCREATEDATETIME,
      //       'scanned_cert_num': self.SCANNED_CERT_NUM,
      //       'issuer_count': self.ISSUER_COUNT,
      //       'key_size_count': self.KEY_SIZE_COUNT,
      //       'key_type_count': self.KEY_TYPE_COUNT,
      //       'validation_period_count': self.VALIDATION_PERIOD_COUNT,
      //       'expired_percent': self.EXPIRED_PERCENT,
      //   }

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
      },
      // Pie Chart data
      myChartData: {
        labels: ['Label 1', 'Label 2', 'Label 3'],
        data: [15, 80, 5],
      },
      myChartOptions: {
        title: {
          subtext: 'Custom Subtitle',
        },
        // Add any other custom options you want to pass
      }
      // ...

    };
  },
  created() {
    this.getList();
    // this.startAutoRefresh();
  },
  beforeDestroy() {
    this.stopAutoRefresh();
  },
  methods: {
    /** 查询部门列表 */
    getList() {
      this.loading = true;
      listCertAnalysisResult(this.queryParams).then(response => {
        // this.scanList = this.handleTree(response.data, "scanId");
        // this.certResultList = response.data;

        this.certResultList = response.data.map(item => {
          try {
                // console.log(typeof(item.issuer_count))
                // console.log(typeof(item.key_size_count))
                // console.log(typeof(item.key_type_count))
                // console.log(typeof(item.validation_period_count))
                const issuerCountData = item.issuer_count ? item.issuer_count : "{}";
                const keySizeCountData = item.key_size_count ? item.key_size_count : "{}";
                const keyTypeCountData = item.key_type_count ? item.key_type_count : "{}";
                const validationPeriodCountData = item.validation_period_count ? item.validation_period_count : "{}";

                // 构建 chartData 列表
                const chartDataList = [
                  { labels: Object.keys(issuerCountData), data: Object.values(issuerCountData) },
                  { labels: Object.keys(keySizeCountData), data: Object.values(keySizeCountData) },
                  { labels: Object.keys(keyTypeCountData), data: Object.values(keyTypeCountData) },
                  { labels: Object.keys(validationPeriodCountData), data: Object.values(validationPeriodCountData) },
                ];

                // 返回新的对象，包括原有的属性和新构建的 chartDataList
                console.log(chartDataList)
                return { ...item, chartDataList };

              } catch (error) {
                console.error("Error parsing JSON:", error);
              }
        });

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


    updateChartData() {
      // 从外部更新数据和选项
      this.myChartData = {
        labels: ['Updated Label 1', 'Updated Label 2', 'Updated Label 3'],
        data: [40, 30, 30],
      };

      this.myChartOptions = {
        title: {
          subtext: 'Updated Subtitle',
        },
        // Add any other custom options
      };
    },
  },
};
</script>
