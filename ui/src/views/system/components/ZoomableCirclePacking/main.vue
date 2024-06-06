<template>
  <div ref="chartContainer" class="chart-container"></div>
</template>

<script>
import * as d3 from '@types/d3';

export default {
  props: {
    data: {
      type: Array,
      required: true
    }
  },
  mounted() {
    this.drawChart();
  },
  methods: {
    drawChart() {
      // 清空容器
      d3.select(this.$refs.chartContainer).html("");

      // 创建SVG容器
      const svg = d3.select(this.$refs.chartContainer)
                    .append("svg")
                    .attr("width", 400)
                    .attr("height", 200);
      
      // 添加圆形，这里只是一个简单的例子
      svg.selectAll("circle")
         .data(this.data)
         .enter()
         .append("circle")
         .attr("cx", (d, i) => i * 50 + 50)
         .attr("cy", d => 150 - d * 10)
         .attr("r", 20)
         .style("fill", "steelblue");
    }


  },
  watch: {
    data: {
      handler(newVal) {
        // 数据变化时重新绘制图表
        this.drawChart();
      },
      deep: true
    }
  }
}
</script>

<style scoped>
.chart-container {
  /* 添加样式以适应你的需要 */
}
</style>

