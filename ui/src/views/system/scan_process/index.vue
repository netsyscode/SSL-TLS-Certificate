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
            v-for="scanStatus in dict.type.sys_scan_status"
            :key="scanStatus.value"
            :label="scanStatus.label"
            :value="scanStatus.value"
          />
        </el-select>
      </el-form-item>

      <el-form-item label="扫描日期范围" prop="scanDateRange">
        <el-date-picker
          v-model="queryParams.scanDateRange"
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
          @click="toggleShowTableAll"
        >全部展开/隐藏</el-button>
      </el-col>
      <right-toolbar :showSearch.sync="showSearch" @queryTable="getList"></right-toolbar>
    </el-row>


    <!-- Create tables based on scan types -->
    <div
      v-for="scanType in dict.type.sys_scan_type"
      :key="scanType.value"
    >
      <div>
        <h2 style="display: inline-block; margin-right: 10px;">证书扫描进程列表：{{ scanType.label }} </h2>
        <span style="display: inline-block;">
          <el-button
          type="info"
          plain
          icon="el-icon-sort"
          size="mini"
          @click="toggleShowTable(scanType.value)"
          >展开/隐藏</el-button>
        </span>
      </div>

      <el-table 
        v-show="isShow[scanType.value]"
        :v-loading="loading"
        :data="scanList[scanType.value]"
        :tree-props="{children: 'children', hasChildren: 'hasChildren'}"
        :default-sort="{prop: 'name', order: 'ascending'}"
      >
      <el-table-column prop="id" label="扫描ID" width="200"></el-table-column>
      <el-table-column prop="name" label="扫描名称" width="100" sortable></el-table-column>
      <el-table-column prop="num_threads" label="线程数量" align="center" width="100"></el-table-column>

      <el-table-column prop="startTime" label="开始时间" align="center" width="230" sortable>
        <template slot-scope="scope">
          <span>{{ parseTime(scope.row.startTime) }}</span>
        </template>
      </el-table-column>
      <el-table-column prop="scan_time_in_seconds" label="运行时间(秒)" align="center" width="80"></el-table-column>
      <el-table-column label="结束时间" align="center" prop="endTime" width="230">
        <template slot-scope="scope">
          <span>{{ parseTime(scope.row.endTime) }}</span>
        </template>
      </el-table-column>
      
      <el-table-column prop="status" label="扫描状态" align="center" width="100" sortable :sort-method="sortStatus">
        <template slot-scope="scope">
          <dict-tag :options="dict.type.sys_scan_status" :value="scope.row.status"/>
        </template>
      </el-table-column>
      
      <el-table-column v-if="scanType.value==0" prop="scanned_domains" label="扫描域名数" align="center" width="100"></el-table-column>
      <el-table-column v-if="scanType.value==1" prop="scanned_ips" label="扫描IP数" align="center" width="100"></el-table-column>
      <el-table-column v-if="scanType.value==2" prop="scan_log_name" label="扫描CT日志名称" align="center" width="100">
        <template slot-scope="scope">
          <dict-tag :options="dict.type.ct_log_info" :value="scope.row.scan_log_name"/>
        </template>
      </el-table-column>
      <el-table-column v-if="scanType.value==2" prop="scanned_entries" label="扫描记录数" align="center" width="100"></el-table-column>

      <el-table-column prop="successes" label="获取成功" align="center" width="100"></el-table-column>
      <el-table-column prop="errors" label="获取失败" align="center" width="100"></el-table-column>
      <el-table-column prop="scanned_certs" label="获取证书数量" align="center" width="100"></el-table-column>

      <el-table-column label="操作" align="center" class-name="small-padding fixed-width">
        <template slot-scope="scope">
          <el-button
            v-if="scope.row.status==0"
            size="mini"
            type="text"
            icon="el-icon-video-pause"
            @click="pauseScan(scope.row)"
            v-hasPermi="['system:scan_process:pause']"
            >暂停进程</el-button>

            <el-button
            v-if="scope.row.status==3"
            size="mini"
            type="text"
            icon="el-icon-video-play"
            @click="resumeScan(scope.row)"
            v-hasPermi="['system:scan_process:resume']"
            >恢复进程</el-button>

          <el-button
            v-if="scope.row.status==0 || scope.row.status==3"
            size="mini"
            type="text"
            icon="el-icon-circle-close"
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
            icon="el-icon-view"
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
        v-if="isShow[scanType.value] && total[scanType.value]>0"
        :total="total[scanType.value]"
        :page.sync="queryParams.pageNum[scanType.value]"
        :limit.sync="queryParams.pageSize"
        @pagination="getList"
      />
      <el-divider />
    </div>

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
            <el-form-item label="扫描方式" prop="scanType">
                <el-select v-model="form.scanType" placeholder="选择扫描方式">
                  <el-option
                    v-for="scanType in dict.type.sys_scan_type"
                    :key="scanType.value"
                    :label="scanType.label"
                    :value="scanType.value"
                  />
                </el-select>
            </el-form-item>
          </el-col>
        </el-row>

        <!-- Common configs -->
        <el-row>
          <el-col :span="50">
            <el-form-item label="代理IP地址" prop="proxyAddress">
              <el-input v-model.lazy="form.proxyAddress" :maxlength="20" />
            </el-form-item>
          </el-col>
        </el-row>

        <el-row>
          <el-col :span="50">
            <el-form-item label="代理端口" prop="proxyPort">
              <el-input-number v-model.lazy="form.proxyPort" :min="1" :max="50000"/>
            </el-form-item>
          </el-col>
        </el-row>

        <el-row>
          <el-col :span="50">
            <el-form-item label="扫描超时设置" prop="timeout">
              <el-input-number v-model.lazy="form.timeout" :min="0" :max="10"/>
            </el-form-item>
          </el-col>
        </el-row>

        <el-row>
          <el-col :span="50">
            <el-form-item label="扫描重试次数" prop="retryTimes">
              <el-input-number v-model.lazy="form.retryTimes" :min="1" :max="5"/>
            </el-form-item>
          </el-col>
        </el-row>

        <el-row>
          <el-col :span="50">
            <el-form-item label="扫描线程数量" prop="scanThreadNum">
              <el-input-number v-model.lazy="form.scanThreadNum" :min="1" :max="100"/>
            </el-form-item>
          </el-col>
        </el-row>


        <!-- Scan type based configs -->
        <div v-show="form.scanType==0">
          <el-row>
            <el-col :span="50">
              <el-form-item label="扫描域名数量" prop="scanDomainNum">
                <el-input-number v-model="form.scanDomainNum" :min="1" :max="getMaxValue" :step="100"/>
              </el-form-item>
            </el-col>
          </el-row>

          <el-row>
            <el-col :span="50">
              <el-form-item label="域名列表文件" prop="scanDomainFile">
                <el-upload
                  v-model="form.scanDomainFile"
                  class="upload-demo"
                  action="/your/upload/api"
                  :on-success="handleSuccess"
                  :before-upload="beforeUpload"
                  :show-file-list="false"
                >
                <input type="file" style="display: none" ref="fileInput" @change="handleFileChange" />
                <el-button size="small" type="primary">点击上传</el-button>
                </el-upload>
              </el-form-item>
            </el-col>
          </el-row>
        </div>

        <div v-show="form.scanType==1">
          <el-row>
            <el-col :span="50">
              <el-form-item label="IP列表文件" prop="scanIpFile">
                <el-upload
                v-model="form.scanIpFile"
                class="upload-demo"
                action="/your/upload/api"
                :on-success="handleSuccess"
                :before-upload="beforeUpload"
                :show-file-list="false"
                >
                <el-button size="small" type="primary">点击上传</el-button>
                </el-upload>
              </el-form-item>
            </el-col>
          </el-row>
        </div>

        <div v-show="form.scanType==2">
          <el-row>
            <el-col :span="50">
              <el-form-item label="扫描日志" prop="ctLog">
                  <el-select v-model="form.ctLog" placeholder="选择扫描日志">
                    <el-option
                      v-for="ctLog in dict.type.ct_log_info"
                      :key="ctLog.value"
                      :label="ctLog.label"
                      :value="ctLog.value"
                    />
                  </el-select>
              </el-form-item>
            </el-col>
          </el-row>

          <el-row>
            <el-col :span="25">
              <el-form-item label="扫描区间起始" prop="startValue">
                <el-input-number v-model="form.startValue" :min="0" :max="getMaxValue" :step="1000" />
              </el-form-item>
            </el-col>
            <el-col :span="25">
              <el-form-item label="扫描区间终止" prop="endValue">
                <el-input-number v-model="form.endValue" :min="0" :max="getMaxValue" :step="1000" />
              </el-form-item>
            </el-col>
          </el-row>
        </div>

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
import { retriveDictMap } from "@/utils/dict/DictCopy";
import { validURL } from "@/utils/validate";
import Treeselect from "@riophae/vue-treeselect";
import "@riophae/vue-treeselect/dist/vue-treeselect.css";

export default {
  name: "ScanProcess",
  dicts: ['sys_scan_type', 'sys_scan_status', 'ct_log_info'],
  components: { Treeselect },
  data() {
    return {
      // 深度拷贝dict
      parseDict: {},
      // 遮罩层
      loading: true,
      // 显示搜索条件
      showSearch: true,
      // 表格树数据
      scanList: {},
      // 弹出层标题
      title: "",
      // 是否显示弹出层
      open: false,
      // 是否展开，默认全部展开
      isShowAll : true,
      isShow: {},
      // 查询参数
      queryParams: {
        pageNum: {},
        pageSize: 10,
        scanProcessName: undefined,
        scanStatus: undefined,
        scanDateRange : [],
      },
      // 总条数
      total: {},
      // 表单参数
      form: {
        proxyAddress : "127.0.0.1",
        proxyPort : 33210,
        timeout : 3,
        retryTimes : 3,
        scanThreadNum : 100,
      },
      // 表单校验
      rules: undefined,
      baseRule: {
        scanName: [
          { required: true, message: "扫描名称不能为空", trigger: "blur" }
        ],
        scanType: [
          { required: true, message: "扫描方式不能为空", trigger: "blur" }
        ],
        proxyAddress: [
          { validator: this.validateAddress, trigger: 'blur' }
        ],
        timeout: [
          { required: true, message: "超时设置不能为空", trigger: "blur" }
        ],
        retryTimes: [
          { required: true, message: "重试设置不能为空", trigger: "blur" }
        ],
        scanThreadNum: [
          { required: true, message: "扫描线程分配数量不能为空", trigger: "blur" }
        ],
      },
    };
  },
  mounted() {
    // pass
  },
  created() {
    this.startAutoRefresh();
    this.rules = this.getScanRules(undefined);
    retriveDictMap(this.dict.type).then(response => {
      this.parseDict = response
      this.parseDict.sys_scan_type.forEach(scanType => {
        this.$set(this.queryParams.pageNum, scanType.value, 1);
        this.$set(this.isShow, scanType.value, true);
        this.$set(this.scanList, scanType.value, []);
        this.$set(this.total, scanType.value, 0);
      });
      this.getList();
    });
  },
  beforeDestroy() {
    this.stopAutoRefresh();
  },
  computed: {
    getMaxValue() {
      return 1000000000;
    },
    scanDomainRules() {
      let targetRules = { ...this.baseRule };
      targetRules["scanDomainNum"] = [
        { required: true, message: "扫描域名数量不能为空", trigger: "blur" },
      ];
      return targetRules;
    },
    scanIpRules() {
      let targetRules = { ...this.baseRule };
      targetRules["scanIpFile"] = [
        // { required: true, message: "扫描IP文件不能为空", trigger: "blur" },
      ];
      return targetRules;
    },
    scanCtRules() {
      let targetRules = { ...this.baseRule };
      targetRules["ctLog"] = [
        { required: true, message: "扫描日志不能为空", trigger: "blur" },
      ];
      targetRules["startValue"] = [
        { required: true, message: "起始不能为空", trigger: "blur" },
        { validator: this.validateStartValue, trigger: 'blur' },
      ];
      targetRules["endValue"] = [
        { required: true, message: "终止不能为空", trigger: "blur" },
        { validator: this.validateEndValue, trigger: 'blur' },
      ];
      return targetRules;
    }
  },
  watch: {
    'form.scanType': function(newValue, oldValue) {
      console.log(`Value changed from ${oldValue} to ${newValue}`);
      this.rules = this.getScanRules(newValue);
    },
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
      this.parseDict.sys_scan_type.forEach(scanType => {
        this.queryParams.pageNum[scanType.value] = 1;
      })
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
      listScanProcess(this.addDateRange(this.queryParams, this.queryParams.scanDateRange)).then(response => {
        this.parseDict.sys_scan_type.forEach(scanType => {
          this.scanList[scanType.value] = response.data[scanType.value];
          this.total[scanType.value] = response.total[scanType.value];
        });
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
    toggleShowTableAll() {
      this.isShowAll = !this.isShowAll;
      this.parseDict.sys_scan_type.forEach(scanType => {
        this.isShow[scanType.value] = this.isShowAll;
      });
    },
    toggleShowTable(type) {
      this.isShow[type] = !this.isShow[type];
    },
    sortStatus(a, b) {
      return b - a;
    },
    getScanRules(type) {
      const rulesMap = {
        undefined: this.baseRule,
        0: this.scanDomainRules,
        1: this.scanIpRules,
        2: this.scanCtRules,
      };
      return rulesMap[type] || null;
    },
    validateAddress(rule, value, callback) {
      this.$nextTick(() => {
        if (!validURL(value)) {
          callback();
          // callback(new Error('代理服务器地址格式错误'));
        } else {
          callback();
        }
      });
    },
    validateStartValue(rule, value, callback) {
      this.$nextTick(() => {
        if (value >= this.form.endValue) {
          callback(new Error('开始值必须小于结束值'));
        } else {
          callback();
        }
      });
    },
    validateEndValue(rule, value, callback) {
      this.$nextTick(() => {
        if (value <= this.form.startValue) {
          callback(new Error('结束值必须大于开始值'));
        } else {
          callback();
        }
      });
    },

    // TODO: handle file upload
    // 文件输入框内容改变时的处理函数
    handleFileChange(event) {
      const input = event.target;
      const file = input.files[0];

      // 更新文件路径显示文本框的值
      this.selectedFilePath = file ? file.name : '';
    },
    handleSuccess(response, file, fileList) {
      // 处理文件上传成功的回调
      console.log(response, file, fileList);
    },
    beforeUpload(file) {
      // 在上传之前的钩子，可以进行一些自定义的验证
      const isAllowedType = file.type === 'image/jpeg' || file.type === 'image/png';
      if (!isAllowedType) {
        this.$message.error('只能上传JPEG/PNG格式的图片');
      }
      return isAllowedType;
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
        proxyAddress : "127.0.0.1",
        proxyPort : 33210,
        timeout : 3,
        retryTimes : 3,
        scanThreadNum: 100,

        scanName: undefined,
        scanType: undefined,
        scanDomainNum: undefined,
        scanDomainFile: undefined,
        scanIpFile: undefined,
        ctLog: undefined,
        startValue: undefined,
        endValue: undefined,
      };
      this.resetForm("form");
    },
  },
};
</script>
