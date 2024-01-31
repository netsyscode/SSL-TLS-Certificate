<!-- MultiEChartsPieChart.vue -->
<template>
    <div class="pie-chart-container">

    <el-table :data="[chartDataList]" >

        <el-table-column label="扫描证书CA分布" width="300">
          <template>
            <e-charts-pie-chart :chartData="chartDataList[0]"></e-charts-pie-chart>
          </template>
        </el-table-column>
        <el-table-column label="证书密钥长度统计" width="300">
          <template>
            <e-charts-pie-chart :chartData="chartDataList[1]"></e-charts-pie-chart>
          </template>
        </el-table-column>
        <el-table-column label="证书密钥种类统计" width="300">
          <template>
            <e-charts-pie-chart :chartData="chartDataList[2]"></e-charts-pie-chart>
          </template>
        </el-table-column>
        <el-table-column label="证书有效时长统计" width="300">
          <template>
            <e-charts-pie-chart :chartData="chartDataList[3]"></e-charts-pie-chart>
          </template>
        </el-table-column>
        
      </el-table>
    </div>
  </template>

  <script>
  import EChartsPieChart from './PieChart';
  
  export default {
    components: {
      EChartsPieChart,
    },
    props: {
      chartDataList: {
        type: Array,
        default: () => [],
      },
      chartTitleList: {
        type: Array,
        default: () => [],
      },
    },
    mounted() {
        this.debug();
    },
    methods: {
        debug() {
            console.log(this.chartDataList)
        },
    },
  };
  </script>
  
  <style scoped>
  .pie-chart-container {
    display: flex;
    flex-wrap: wrap;
  }
  </style>
  