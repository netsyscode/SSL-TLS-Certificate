<!-- MultiEChartsPieChart.vue -->
<template>
    <div class="pie-chart-container">

    <el-table :data="[chartDataList]" >

        <el-table-column label="xxx" width="300">
          <template>
            <e-charts-pie-chart :chartData="chartDataList[0]"></e-charts-pie-chart>
          </template>
        </el-table-column>
        <el-table-column label="xxx" width="300">
          <template>
            <e-charts-pie-chart :chartData="chartDataList[1]"></e-charts-pie-chart>
          </template>
        </el-table-column>
        <el-table-column label="xxx" width="300">
          <template>
            <e-charts-pie-chart :chartData="chartDataList[2]"></e-charts-pie-chart>
          </template>
        </el-table-column>
        <el-table-column label="xxx" width="300">
          <template>
            <e-charts-pie-chart :chartData="chartDataList[3]"></e-charts-pie-chart>
          </template>
        </el-table-column>
        
      </el-table>
    </div>
  </template>

  <script>
  import EChartsPieChart from './PieChart.vue';
  
  export default {
    components: {
      EChartsPieChart,
    },
    props: {
      chartDataList: {
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
  