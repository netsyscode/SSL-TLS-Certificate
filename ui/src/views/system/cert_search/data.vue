<template>
  <div class="app-container main">
    <el-row :gutter="20">
      <el-col :sm="24" :lg="24" style="padding-left: 20px">
        <h2>证书详细信息</h2>

        <template>
          <el-card>
            <div slot="header">Certificate Information</div>
            <div class="certificate-item">
              <strong>Certificate:</strong>

              <div class="indent">
                <div v-for="(value, key) in certData" :key="key">

                  <strong style="display: inline-block;"> {{ key }}:</strong>

                  <template v-if="isObject(value)" class="indent">
                    <div v-for="(subValue, subKey) in value" :key="subKey">
                      <strong style="display: inline-block;">{{ subKey }}:</strong>
                      <span v-if="checkKeyInDict(subKey)[0]" style="display: inline-block;">
                        <dict-tag :options="checkKeyInDict(subKey)[1]" :value="subValue"/>
                      </span>
                      <span v-else>
                        <code class="code-block">{{ subValue }}</code>
                      </span>
                    </div>
                  </template>

                  <template v-else>
                    <span v-if="checkKeyInDict(key)[0]" style="display: inline-block;">
                      <dict-tag :options="checkKeyInDict(key)[1]" :value="value"/>
                    </span>
                    <span v-else>
                      <code class="code-block">{{ value }}</code>
                    </span>
                  </template>

                </div>
              </div>

            </div>
          </el-card>
        </template>

      </el-col>
    </el-row>

    <el-divider />

    <el-row :gutter="20">
      <el-col :sm="24" :lg="24" style="padding-left: 20px">
        <h2>证书历史扫描记录</h2>
      </el-col>
    </el-row>

    <el-table
      v-if="refreshTable"
      v-loading="loading"
      :data="scanInfoList"
      row-key="cert_id"
      :default-expand-all="isExpandAll"
      :tree-props="{children: 'children', hasChildren: 'hasChildren'}"
      >

      <el-table-column prop="cert_id" label="扫描ID" width="200"></el-table-column>
      <!-- <el-table-column prop="scan_date" label="扫描名称" width="100"></el-table-column> -->
      <!-- <el-table-column prop="scanType" label="扫描类型" align="center" width="100">
        <template slot-scope="scope">
          <dict-tag :options="dict.type.sys_scan_type" :value="scope.row.scanType"/>
        </template>
      </el-table-column> -->

      <el-table-column prop="scan_date" label="扫描时间" align="center" width="230">
        <!-- <template slot-scope="scope">
          <span>{{ parseTime(scope.row.startTime) }}</span>
        </template> -->
      </el-table-column>
      <el-table-column prop="scan_domain" label="来源域名" align="center" width="300"></el-table-column>

    </el-table>

    <el-divider />

    <el-row :gutter="20">
      <el-col :sm="24" :lg="24" style="padding-left: 20px">
        <h2>证书链关系</h2>
      </el-col>
    </el-row>

    <el-divider />

    <el-row :gutter="20">
      <el-col :xs="24" :sm="24" :md="24" :lg="24">
        <h2>证书吊销状态</h2>
      </el-col>
    </el-row>
  </div>

</template>

<script>
import { getCertInfo } from "@/api/system/cert_search";

export default {
  name: "CertView",
  dicts: ['sys_cert_type', 'sys_key_type'],
  data() {
    return {
      // 遮罩层
      loading: true,
      refreshTable: true,
      isExpandAll: true,
      // 弹出层标题
      title: "",
      // 是否显示弹出层
      open: false,
      // 证书信息
      certData: {},
      scanInfoList: [],
    };
  },
  created() {
    const certId = this.$route.params && this.$route.params.cert_id;
    this.getCert(certId);
  },
  methods: {
    /** 查询证书详细 */
    getCert(certId) {
      this.loading = true;
      getCertInfo(certId).then(response => {
        this.certData = response.cert_data
        this.scanInfoList = response.scan_info
        this.loading = false;
      });
    },
    isObject(value) {
      return value !== null && typeof value === 'object';
    },
    checkKeyInDict(key) {
      if (key === "cert_type") {
        return [true, this.dict.type.sys_cert_type || ''];
      } else if (key === "subject_pub_key_algo") {
        return [true, this.dict.type.sys_key_type || ''];
      } else {
        return [false, ''];
      }
    }
  }
};
</script>

<style scoped lang="scss">
.main {
  blockquote {
    padding: 10px 20px;
    margin: 0 0 20px;
    font-size: 17.5px;
    border-left: 5px solid #eee;
  }
  hr {
    margin-top: 20px;
    margin-bottom: 20px;
    border: 0;
    border-top: 1px solid #eee;
  }
  .col-item {
    margin-bottom: 20px;
  }

  ul {
    padding: 0;
    margin: 0;
  }

  font-family: "open sans", "Helvetica Neue", Helvetica, Arial, sans-serif;
  font-size: 13px;
  color: #676a6c;
  overflow-x: hidden;

  ul {
    list-style-type: none;
  }

  h4 {
    margin-top: 0px;
  }

  h2 {
    margin-top: 10px;
    font-size: 26px;
    font-weight: 100;
  }

  p {
    margin-top: 10px;

    b {
      font-weight: 700;
    }
  }

  .update-log {
    ol {
      display: block;
      list-style-type: decimal;
      margin-block-start: 1em;
      margin-block-end: 1em;
      margin-inline-start: 0;
      margin-inline-end: 0;
      padding-inline-start: 40px;
    }
  }
  .certificate-item {
  margin-bottom: 8px;
  }
  strong {
    font-family: 'Courier New', monospace;
    background-color: #f4f4f4;
    padding: 2px 2px;
    border-radius: 4px;
    display: inline-block;
    line-height: 2.5;
  }
  .code-block {
    font-family: 'Courier New', monospace;
    padding: 2px 4px;
    border-radius: 4px;
    display: inline-block;
  }

}
</style>

