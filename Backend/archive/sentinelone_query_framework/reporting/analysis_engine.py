"""
Analysis and Reporting Engine
Generates comprehensive reports, tracks metrics, and provides actionable insights
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union, Any
from pathlib import Path
import pandas as pd
from collections import defaultdict, Counter

class AnalysisEngine:
    """
    Comprehensive analysis and reporting engine for SentinelOne field extraction validation
    """
    
    def __init__(self, output_dir: str = "/Users/nathanial.smalley/projects/jarvis_coding/reports"):
        """
        Initialize Analysis Engine
        
        Args:
            output_dir: Directory for saving reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        self._setup_logging()
        
        # Metrics storage
        self.metrics_history = []
        self.current_session = {
            'session_id': datetime.utcnow().strftime('%Y%m%d_%H%M%S'),
            'start_time': datetime.utcnow(),
            'metrics': {}
        }
        
    def _setup_logging(self):
        """Configure logging for analysis engine"""
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def analyze_field_extraction_results(self, validation_results: List[Dict]) -> Dict:
        """
        Analyze field extraction validation results
        
        Args:
            validation_results: List of validation results from field validator
            
        Returns:
            Comprehensive analysis report
        """
        if not validation_results:
            return {'error': 'No validation results provided'}
        
        analysis = {
            'summary': self._generate_summary_statistics(validation_results),
            'field_coverage_analysis': self._analyze_field_coverage(validation_results),
            'format_compatibility_analysis': self._analyze_format_compatibility(validation_results),
            'ocsf_compliance_analysis': self._analyze_ocsf_compliance(validation_results),
            'category_performance': self._analyze_category_performance(validation_results),
            'recommendations': self._generate_recommendations(validation_results),
            'detailed_results': validation_results
        }
        
        # Store metrics
        self.current_session['metrics']['field_extraction_analysis'] = analysis
        
        return analysis
    
    def analyze_query_performance(self, query_results: List[Dict]) -> Dict:
        """
        Analyze SDL query performance and effectiveness
        
        Args:
            query_results: List of query execution results
            
        Returns:
            Query performance analysis
        """
        if not query_results:
            return {'error': 'No query results provided'}
        
        analysis = {
            'query_statistics': self._analyze_query_statistics(query_results),
            'response_time_analysis': self._analyze_response_times(query_results),
            'event_retrieval_analysis': self._analyze_event_retrieval(query_results),
            'error_analysis': self._analyze_query_errors(query_results),
            'optimization_suggestions': self._suggest_query_optimizations(query_results)
        }
        
        # Store metrics
        self.current_session['metrics']['query_performance_analysis'] = analysis
        
        return analysis
    
    def analyze_parser_effectiveness(self, sdk_results: List[Dict]) -> Dict:
        """
        Analyze parser effectiveness using SDK results
        
        Args:
            sdk_results: Results from SentinelOne SDK queries
            
        Returns:
            Parser effectiveness analysis
        """
        if not sdk_results:
            return {'error': 'No SDK results provided'}
        
        analysis = {
            'extraction_metrics': self._calculate_extraction_metrics(sdk_results),
            'field_distribution': self._analyze_field_distribution(sdk_results),
            'parser_rankings': self._rank_parsers_by_effectiveness(sdk_results),
            'improvement_opportunities': self._identify_improvement_opportunities(sdk_results),
            'success_patterns': self._identify_success_patterns(sdk_results)
        }
        
        # Store metrics
        self.current_session['metrics']['parser_effectiveness_analysis'] = analysis
        
        return analysis
    
    def generate_comprehensive_report(self, 
                                    validation_results: List[Dict] = None,
                                    query_results: List[Dict] = None,
                                    sdk_results: List[Dict] = None) -> Dict:
        """
        Generate comprehensive analysis report combining all data sources
        
        Args:
            validation_results: Field validation results
            query_results: Query performance results
            sdk_results: SDK query results
            
        Returns:
            Comprehensive report
        """
        report = {
            'report_metadata': {
                'generated_at': datetime.utcnow().isoformat(),
                'session_id': self.current_session['session_id'],
                'report_type': 'comprehensive_analysis'
            },
            'executive_summary': {},
            'detailed_analysis': {},
            'recommendations': [],
            'metrics_dashboard': {}
        }
        
        # Analyze each data source
        if validation_results:
            field_analysis = self.analyze_field_extraction_results(validation_results)
            report['detailed_analysis']['field_extraction'] = field_analysis
        
        if query_results:
            query_analysis = self.analyze_query_performance(query_results)
            report['detailed_analysis']['query_performance'] = query_analysis
        
        if sdk_results:
            parser_analysis = self.analyze_parser_effectiveness(sdk_results)
            report['detailed_analysis']['parser_effectiveness'] = parser_analysis
        
        # Generate executive summary
        report['executive_summary'] = self._generate_executive_summary(report['detailed_analysis'])
        
        # Consolidate recommendations
        report['recommendations'] = self._consolidate_recommendations(report['detailed_analysis'])
        
        # Create metrics dashboard
        report['metrics_dashboard'] = self._create_metrics_dashboard(report['detailed_analysis'])
        
        # Save report
        report_file = self.output_dir / f"comprehensive_report_{self.current_session['session_id']}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        self.logger.info(f"Comprehensive report saved: {report_file}")
        
        return report
    
    def track_metrics_over_time(self, current_metrics: Dict) -> Dict:
        """
        Track metrics over time and identify trends
        
        Args:
            current_metrics: Current metrics snapshot
            
        Returns:
            Trend analysis
        """
        # Add timestamp
        timestamped_metrics = {
            'timestamp': datetime.utcnow().isoformat(),
            'session_id': self.current_session['session_id'],
            **current_metrics
        }
        
        self.metrics_history.append(timestamped_metrics)
        
        # Analyze trends if we have historical data
        if len(self.metrics_history) > 1:
            return self._analyze_metric_trends()
        
        return {'message': 'Insufficient historical data for trend analysis'}
    
    def _generate_summary_statistics(self, results: List[Dict]) -> Dict:
        """Generate summary statistics from validation results"""
        total_generators = len(results)
        successful_validations = len([r for r in results if r.get('status') == 'analyzed'])
        
        alignment_scores = []
        format_compatibility_scores = []
        field_coverage_scores = []
        
        for result in results:
            if result.get('status') == 'analyzed' and 'alignment_analysis' in result:
                analysis = result['alignment_analysis']
                
                if 'overall_score' in analysis:
                    alignment_scores.append(analysis['overall_score'])
                
                if 'format_compatibility' in analysis:
                    format_compatibility_scores.append(
                        analysis['format_compatibility'].get('compatibility_score', 0)
                    )
                
                if 'field_coverage' in analysis:
                    field_coverage_scores.append(
                        analysis['field_coverage'].get('coverage_percentage', 0)
                    )
        
        return {
            'total_generators': total_generators,
            'successful_validations': successful_validations,
            'validation_success_rate': (successful_validations / total_generators * 100) if total_generators > 0 else 0,
            'average_alignment_score': sum(alignment_scores) / len(alignment_scores) if alignment_scores else 0,
            'average_format_compatibility': sum(format_compatibility_scores) / len(format_compatibility_scores) if format_compatibility_scores else 0,
            'average_field_coverage': sum(field_coverage_scores) / len(field_coverage_scores) if field_coverage_scores else 0,
            'score_distribution': {
                'excellent': len([s for s in alignment_scores if s >= 90]),
                'good': len([s for s in alignment_scores if 70 <= s < 90]),
                'fair': len([s for s in alignment_scores if 50 <= s < 70]),
                'poor': len([s for s in alignment_scores if s < 50])
            }
        }
    
    def _analyze_field_coverage(self, results: List[Dict]) -> Dict:
        """Analyze field coverage patterns"""
        all_generator_fields = []
        all_parser_fields = []
        common_field_counts = []
        missing_fields_counter = Counter()
        
        for result in results:
            if result.get('status') == 'analyzed' and 'alignment_analysis' in result:
                field_coverage = result['alignment_analysis'].get('field_coverage', {})
                
                all_generator_fields.append(field_coverage.get('generator_fields', 0))
                all_parser_fields.append(field_coverage.get('parser_expected_fields', 0))
                common_field_counts.append(field_coverage.get('common_fields', 0))
                
                # Track missing fields
                missing_fields = field_coverage.get('missing_fields', [])
                for field in missing_fields:
                    missing_fields_counter[field] += 1
        
        return {
            'avg_generator_fields': sum(all_generator_fields) / len(all_generator_fields) if all_generator_fields else 0,
            'avg_parser_expected_fields': sum(all_parser_fields) / len(all_parser_fields) if all_parser_fields else 0,
            'avg_common_fields': sum(common_field_counts) / len(common_field_counts) if common_field_counts else 0,
            'most_missing_fields': missing_fields_counter.most_common(10),
            'field_coverage_distribution': {
                'high_coverage': len([r for r in results if self._get_field_coverage_score(r) >= 80]),
                'medium_coverage': len([r for r in results if 50 <= self._get_field_coverage_score(r) < 80]),
                'low_coverage': len([r for r in results if self._get_field_coverage_score(r) < 50])
            }
        }
    
    def _analyze_format_compatibility(self, results: List[Dict]) -> Dict:
        """Analyze format compatibility patterns"""
        format_matches = defaultdict(int)
        format_mismatches = defaultdict(int)
        
        for result in results:
            if result.get('status') == 'analyzed' and 'alignment_analysis' in result:
                format_compat = result['alignment_analysis'].get('format_compatibility', {})
                gen_format = format_compat.get('generator_format', 'unknown')
                parser_format = format_compat.get('parser_format', 'unknown')
                compatible = format_compat.get('compatible', False)
                
                if compatible:
                    format_matches[f"{gen_format} -> {parser_format}"] += 1
                else:
                    format_mismatches[f"{gen_format} -> {parser_format}"] += 1
        
        total_checks = len([r for r in results if self._has_format_analysis(r)])
        compatible_count = sum(format_matches.values())
        
        return {
            'total_format_checks': total_checks,
            'compatible_formats': compatible_count,
            'compatibility_rate': (compatible_count / total_checks * 100) if total_checks > 0 else 0,
            'format_matches': dict(format_matches),
            'format_mismatches': dict(format_mismatches),
            'common_mismatches': list(format_mismatches.most_common(5))
        }
    
    def _analyze_ocsf_compliance(self, results: List[Dict]) -> Dict:
        """Analyze OCSF compliance patterns"""
        compliance_scores = []
        
        for result in results:
            if result.get('parser_info', {}).get('ocsf_compliance'):
                compliance = result['parser_info']['ocsf_compliance']
                compliance_scores.append(compliance.get('compliance_percentage', 0))
        
        if compliance_scores:
            return {
                'parsers_with_ocsf_data': len(compliance_scores),
                'avg_ocsf_compliance': sum(compliance_scores) / len(compliance_scores),
                'high_compliance': len([s for s in compliance_scores if s >= 80]),
                'medium_compliance': len([s for s in compliance_scores if 50 <= s < 80]),
                'low_compliance': len([s for s in compliance_scores if s < 50])
            }
        
        return {'message': 'No OCSF compliance data available'}
    
    def _analyze_category_performance(self, results: List[Dict]) -> Dict:
        """Analyze performance by category"""
        category_stats = defaultdict(lambda: {
            'generators': 0,
            'alignment_scores': [],
            'format_compatibility_scores': [],
            'field_coverage_scores': []
        })
        
        for result in results:
            category = result.get('category', 'unknown')
            category_stats[category]['generators'] += 1
            
            if result.get('status') == 'analyzed' and 'alignment_analysis' in result:
                analysis = result['alignment_analysis']
                
                if 'overall_score' in analysis:
                    category_stats[category]['alignment_scores'].append(analysis['overall_score'])
                
                if 'format_compatibility' in analysis:
                    score = analysis['format_compatibility'].get('compatibility_score', 0)
                    category_stats[category]['format_compatibility_scores'].append(score)
                
                if 'field_coverage' in analysis:
                    score = analysis['field_coverage'].get('coverage_percentage', 0)
                    category_stats[category]['field_coverage_scores'].append(score)
        
        # Calculate averages for each category
        category_performance = {}
        for category, stats in category_stats.items():
            alignment_scores = stats['alignment_scores']
            format_scores = stats['format_compatibility_scores']
            coverage_scores = stats['field_coverage_scores']
            
            category_performance[category] = {
                'generator_count': stats['generators'],
                'avg_alignment_score': sum(alignment_scores) / len(alignment_scores) if alignment_scores else 0,
                'avg_format_compatibility': sum(format_scores) / len(format_scores) if format_scores else 0,
                'avg_field_coverage': sum(coverage_scores) / len(coverage_scores) if coverage_scores else 0
            }
        
        # Rank categories
        ranked_categories = sorted(
            category_performance.items(),
            key=lambda x: x[1]['avg_alignment_score'],
            reverse=True
        )
        
        return {
            'category_performance': category_performance,
            'top_performing_categories': ranked_categories[:5],
            'categories_needing_improvement': ranked_categories[-5:]
        }
    
    def _generate_recommendations(self, results: List[Dict]) -> List[Dict]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Format compatibility recommendations
        format_issues = []
        for result in results:
            if result.get('status') == 'analyzed' and 'alignment_analysis' in result:
                format_compat = result['alignment_analysis'].get('format_compatibility', {})
                if not format_compat.get('compatible', False):
                    format_issues.append(result)
        
        if format_issues:
            recommendations.append({
                'type': 'format_compatibility',
                'priority': 'high',
                'title': 'Fix Format Compatibility Issues',
                'description': f'{len(format_issues)} generators have format compatibility issues',
                'affected_generators': [r['generator'] for r in format_issues[:10]],
                'action_items': [
                    'Review generator output formats',
                    'Update generators to match parser expectations',
                    'Test format changes with parsers'
                ]
            })
        
        # Field coverage recommendations
        low_coverage = []
        for result in results:
            if self._get_field_coverage_score(result) < 50:
                low_coverage.append(result)
        
        if low_coverage:
            recommendations.append({
                'type': 'field_coverage',
                'priority': 'medium',
                'title': 'Improve Field Coverage',
                'description': f'{len(low_coverage)} generators have low field coverage',
                'affected_generators': [r['generator'] for r in low_coverage[:10]],
                'action_items': [
                    'Add missing fields to generators',
                    'Review parser field expectations',
                    'Implement field mapping improvements'
                ]
            })
        
        # OCSF compliance recommendations
        recommendations.append({
            'type': 'ocsf_compliance',
            'priority': 'low',
            'title': 'Enhance OCSF Compliance',
            'description': 'Improve OCSF field mapping in parsers',
            'action_items': [
                'Review OCSF schema requirements',
                'Update parser configurations',
                'Test OCSF field extraction'
            ]
        })
        
        return recommendations
    
    def _get_field_coverage_score(self, result: Dict) -> float:
        """Get field coverage score from result"""
        if result.get('status') == 'analyzed' and 'alignment_analysis' in result:
            return result['alignment_analysis'].get('field_coverage', {}).get('coverage_percentage', 0)
        return 0
    
    def _has_format_analysis(self, result: Dict) -> bool:
        """Check if result has format analysis"""
        return (result.get('status') == 'analyzed' and 
                'alignment_analysis' in result and
                'format_compatibility' in result['alignment_analysis'])
    
    def _generate_executive_summary(self, detailed_analysis: Dict) -> Dict:
        """Generate executive summary from detailed analysis"""
        summary = {
            'key_metrics': {},
            'major_findings': [],
            'critical_issues': [],
            'success_highlights': []
        }
        
        # Extract key metrics
        if 'field_extraction' in detailed_analysis:
            field_summary = detailed_analysis['field_extraction']['summary']
            summary['key_metrics']['validation_success_rate'] = field_summary.get('validation_success_rate', 0)
            summary['key_metrics']['average_alignment_score'] = field_summary.get('average_alignment_score', 0)
        
        # Major findings
        summary['major_findings'] = [
            'Field extraction validation completed across all generators',
            'Format compatibility analysis identified improvement opportunities',
            'Parser effectiveness metrics calculated for optimization'
        ]
        
        return summary
    
    def _consolidate_recommendations(self, detailed_analysis: Dict) -> List[Dict]:
        """Consolidate recommendations from all analyses"""
        all_recommendations = []
        
        for analysis_type, analysis_data in detailed_analysis.items():
            if isinstance(analysis_data, dict) and 'recommendations' in analysis_data:
                recommendations = analysis_data['recommendations']
                if isinstance(recommendations, list):
                    all_recommendations.extend(recommendations)
        
        # Prioritize and deduplicate
        prioritized = sorted(all_recommendations, key=lambda x: x.get('priority', 'low'))
        
        return prioritized
    
    def _create_metrics_dashboard(self, detailed_analysis: Dict) -> Dict:
        """Create metrics dashboard from analyses"""
        dashboard = {
            'overview': {},
            'performance_indicators': {},
            'trends': {},
            'alerts': []
        }
        
        # Extract overview metrics
        if 'field_extraction' in detailed_analysis:
            field_summary = detailed_analysis['field_extraction']['summary']
            dashboard['overview']['total_generators'] = field_summary.get('total_generators', 0)
            dashboard['overview']['validation_success_rate'] = field_summary.get('validation_success_rate', 0)
        
        return dashboard
    
    def save_session_metrics(self):
        """Save current session metrics to file"""
        self.current_session['end_time'] = datetime.utcnow()
        
        metrics_file = self.output_dir / f"session_metrics_{self.current_session['session_id']}.json"
        with open(metrics_file, 'w') as f:
            json.dump(self.current_session, f, indent=2, default=str)
        
        self.logger.info(f"Session metrics saved: {metrics_file}")
    
    def generate_html_report(self, report_data: Dict) -> str:
        """Generate HTML report for better readability"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SentinelOne Query Framework Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; padding: 15px; border-left: 4px solid #007acc; }}
                .metric {{ background-color: #f9f9f9; padding: 10px; margin: 5px 0; border-radius: 3px; }}
                .recommendation {{ background-color: #fff3cd; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .success {{ color: #28a745; }}
                .warning {{ color: #ffc107; }}
                .error {{ color: #dc3545; }}
                table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>SentinelOne Query Framework Analysis Report</h1>
                <p>Generated: {report_data.get('report_metadata', {}).get('generated_at', 'N/A')}</p>
                <p>Session ID: {report_data.get('report_metadata', {}).get('session_id', 'N/A')}</p>
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <div class="metric">
                    <strong>Validation Success Rate:</strong> 
                    {report_data.get('executive_summary', {}).get('key_metrics', {}).get('validation_success_rate', 0):.1f}%
                </div>
                <div class="metric">
                    <strong>Average Alignment Score:</strong> 
                    {report_data.get('executive_summary', {}).get('key_metrics', {}).get('average_alignment_score', 0):.1f}
                </div>
            </div>
            
            <div class="section">
                <h2>Recommendations</h2>
                {self._generate_html_recommendations(report_data.get('recommendations', []))}
            </div>
            
            <div class="section">
                <h2>Detailed Metrics</h2>
                <p>See JSON report for comprehensive details.</p>
            </div>
        </body>
        </html>
        """
        
        html_file = self.output_dir / f"report_{self.current_session['session_id']}.html"
        with open(html_file, 'w') as f:
            f.write(html_content)
        
        self.logger.info(f"HTML report saved: {html_file}")
        return str(html_file)
    
    def _generate_html_recommendations(self, recommendations: List[Dict]) -> str:
        """Generate HTML for recommendations section"""
        if not recommendations:
            return "<p>No specific recommendations at this time.</p>"
        
        html = ""
        for rec in recommendations[:5]:  # Top 5 recommendations
            priority_class = rec.get('priority', 'low')
            html += f"""
            <div class="recommendation">
                <h4>{rec.get('title', 'Recommendation')}</h4>
                <p><strong>Priority:</strong> <span class="{priority_class}">{priority_class.upper()}</span></p>
                <p>{rec.get('description', 'No description')}</p>
            </div>
            """
        
        return html