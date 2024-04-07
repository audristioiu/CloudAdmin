import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';

const D3GrafanaChartCPU = ({ graphiteData }) => {
    const svgRef = useRef();
    const margin = { top: 50, right: 250, bottom: 50, left: 50 };
    const width = 1600 - margin.left - margin.right;
    const height = 600 - margin.top - margin.bottom;

    useEffect(() => {
        if (!graphiteData || graphiteData.length === 0) return;

        const svg = d3.select(svgRef.current);

        const formattedData = graphiteData.map(({ target, datapoints }) => ({
            target,
            datapoints: datapoints.map(([value, timestamp]) => ({ value: value !== null ? value : undefined, timestamp: new Date(timestamp * 1000) }))
        }));
        const minX = d3.min(formattedData, d => d3.min(d.datapoints, dp => dp.timestamp));
        const maxX = d3.max(formattedData, d => d3.max(d.datapoints, dp => dp.timestamp));
        const x = d3.scaleTime()
            .domain([new Date(minX), new Date(maxX)])
            .range([margin.left, width - margin.right]);

        const y = d3.scaleLinear()
            .domain([
                0,
                d3.max(formattedData, d => d3.max(d.datapoints, dp => dp.value))
            ])
            .nice()
            .range([height - margin.bottom, margin.top]);

        const line = d3.line()
            .defined(d => !isNaN(d.value))
            .x(d => x(d.timestamp))
            .y(d => y(d.value));

        
            const colorsArray = [
                "#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd",
                "#8c564b", "#e377c2", "#7f7f7f", "#bcbd22", "#17becf",
                "#aec7e8", "#ffbb78", "#98df8a", "#ff9896", "#c5b0d5",
                "#c49c94", "#f7b6d2", "#c7c7c7", "#dbdb8d", "#9edae5",
                "#393b79", "#637939", "#8c6d31", "#843c39", "#7b4173",
                "#5254a3", "#637939", "#8c6d31", "#843c39", "#7b4173"
              ];
        svg.selectAll('.line')
            .data(formattedData.filter(d => d.datapoints.some(dp => !isNaN(dp.value))))
            .join('path')
            .attr('class', 'line')
            .attr('d', d => line(d.datapoints))
            .attr('fill', 'none')
            .attr('stroke', (d, i) => colorsArray[i]);

        svg.selectAll('.x-axis')
            .data([null])
            .join('g')
            .attr('class', 'x-axis')
            .attr('transform', `translate(0, ${height - margin.bottom})`)
            .call(d3.axisBottom(x).tickFormat(d3.timeFormat('%m/%d %H:%M')));

        svg.selectAll('.y-axis')
            .data([null])
            .join('g')
            .attr('class', 'y-axis')
            .attr('transform', `translate(${margin.left}, 0)`)
            .call(d3.axisLeft(y).tickFormat(d => d));

        svg.selectAll('.legend')
            .data([null])
            .join('g')
            .attr('class', 'legend')
            .attr('transform', `translate(${width - margin.right-400}, ${margin.top+500})`)
            .selectAll('.legend-item')
            .data(formattedData)
            .join('g')
            .attr('class', 'legend-item')
            .attr('transform', (d, i) => `translate(0, ${i * 20})`)
            .each(function (d, i) {
                d3.select(this)
                    .append('rect')
                    .attr('width', 18)
                    .attr('height', 18)
                    .attr('fill', colorsArray[i]);

                d3.select(this)
                    .append('text')
                    .attr('x', 24)
                    .attr('y', 9)
                    .attr('dy', '0.32em')
                    .text(d.target);
            });

        svg.selectAll('.axis-label')
            .data([null])
            .join('text')
            .attr('class', 'axis-label')
            .attr('transform', 'rotate(-90)')
            .attr('y', 0)
            .attr('x', 0 - height / 2)
            .attr('dy', '1em')
            .style('text-anchor', 'middle')
            .text('mcores');

        svg.selectAll('.axis-label-x')
            .data([null])
            .join('text')
            .attr('class', 'axis-label')
            .attr('transform', `translate(${width / 2 }, ${height})`)
            .style('text-anchor', 'middle')
            .text('Timestamp');
    }, [graphiteData]);
    return (
        <svg ref={svgRef} width={width + margin.left + margin.right} height={height + margin.top + margin.bottom}>
            <g className="graph-content" />
            <g className="x-axis" />
            <g className="y-axis" />
        </svg>
    );
};
export default D3GrafanaChartCPU;