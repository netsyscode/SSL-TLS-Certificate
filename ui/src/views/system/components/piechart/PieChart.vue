
<!-- EChartsPieChart.vue -->
<template>
  <div ref="chart" style="width: 100%; height: 400px;"></div>
</template>

<script>
import echarts from 'echarts';

export default {
  props: {
    chartData: {
      type: Object,
      default: () => ({
        labels: [],
        data: [],
      }),
    },
    chartOptions: {
      type: Object,
      default: () => ({}),
    },
  },
  mounted() {
    this.renderChart();
  },
  watch: {
    chartData: 'renderChart',
    chartOptions: 'renderChart',
  },
  methods: {
    renderChart() {
      const chart = echarts.init(this.$refs.chart);
      const { labels, data } = this.chartData;
      // console.log(this.chartData)

      const defaultOptions = {
        title: {
          text: 'Pie Chart',
          subtext: 'Example',
          left: 'center',
        },
        series: [
          {
            name: 'Pie Chart',
            type: 'pie',
            radius: '55%',
            data: labels.map((label, index) => ({ name: label, value: data[index] })),
          },
        ],
      };

      const mergedOptions = { ...defaultOptions, ...this.chartOptions };

      chart.setOption(mergedOptions);
    },
  },
};
</script>
