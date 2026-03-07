"""AWS documentation and blog search — provides the agent with access to
official AWS docs, blog posts, and What's New announcements for authoritative, current answers."""
import logging
import re
import xml.etree.ElementTree as ET
from html import unescape
from urllib.parse import quote_plus
from typing import Optional

import requests

logger = logging.getLogger(__name__)

_SESSION = requests.Session()
_SESSION.headers.update({
    "User-Agent": "CloudPilot/0.1 (AWS Infrastructure Intelligence)",
    "Accept": "application/json, text/html, application/rss+xml",
})
_TIMEOUT = 10


def search_aws_docs(query: str, max_results: int = 5) -> dict:
    """Search official AWS documentation. Uses keyword matching against a comprehensive
    service-to-docs mapping, plus constructs direct search URLs."""
    return _fallback_docs_search(query, max_results)


def search_aws_blog(query: str, max_results: int = 5) -> dict:
    """Search AWS What's New announcements and blog posts for latest launches.
    Uses the AWS What's New RSS feed (always current) and filters by query keywords."""
    try:
        # Primary: AWS What's New RSS feed — always has the latest announcements
        resp = _SESSION.get(
            "https://aws.amazon.com/about-aws/whats-new/recent/feed/",
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            results = _parse_rss_with_filter(resp.text, query, max_results)
            if results:
                return {"query": query, "source": "AWS What's New", "results": results}

        # Fallback: blog API
        resp = _SESSION.get("https://aws.amazon.com/api/dirs/blog-posts/items", params={
            "item.locale": "en_US",
            "size": "25",
            "sort_by": "item.additionalFields.createdDate",
            "sort_order": "desc",
        }, timeout=_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            results = _filter_blog_items(data.get("items", []), query, max_results)
            if results:
                return {"query": query, "source": "AWS Blog", "results": results}

        return _fallback_blog_search(query, max_results)

    except Exception as e:
        logger.warning(f"AWS blog search failed: {e}")
        return _fallback_blog_search(query, max_results)


def _parse_rss_with_filter(xml_text: str, query: str, max_results: int) -> list[dict]:
    """Parse RSS feed XML and filter items by query keywords."""
    results = []
    keywords = [w.lower() for w in query.split() if len(w) > 2]

    try:
        root = ET.fromstring(xml_text)
        for item in root.findall(".//item"):
            title = item.findtext("title", "")
            desc = item.findtext("description", "")
            link = item.findtext("link", "")
            pub_date = item.findtext("pubDate", "")

            # Score by keyword matches in title and description
            text = (title + " " + desc).lower()
            matches = sum(1 for kw in keywords if kw in text)

            if matches > 0 or not keywords:
                results.append({
                    "title": _clean_html(title),
                    "snippet": _clean_html(desc)[:300],
                    "url": link,
                    "date": pub_date,
                    "score": matches,
                })

        # Sort by relevance (keyword matches), then by recency (already in RSS order)
        results.sort(key=lambda x: x.get("score", 0), reverse=True)
        # Remove score from output
        for r in results:
            r.pop("score", None)
        return results[:max_results]
    except ET.ParseError as e:
        logger.warning(f"RSS parse error: {e}")
        return []


def _filter_blog_items(items: list[dict], query: str, max_results: int) -> list[dict]:
    """Filter blog API items by query keywords."""
    keywords = [w.lower() for w in query.split() if len(w) > 2]
    results = []

    for item in items:
        fields = item.get("additionalFields", {})
        title = fields.get("title", "")
        excerpt = fields.get("postExcerpt", "")
        link = fields.get("link", "")

        if not title:
            continue

        text = (title + " " + excerpt).lower()
        matches = sum(1 for kw in keywords if kw in text)

        if matches > 0:
            results.append({
                "title": title,
                "snippet": _clean_html(excerpt)[:300],
                "url": link,
                "date": fields.get("displayDate", fields.get("createdDate", "")),
                "author": fields.get("contributors", ""),
                "score": matches,
            })

    results.sort(key=lambda x: x.get("score", 0), reverse=True)
    for r in results:
        r.pop("score", None)
    return results[:max_results]


def _fallback_docs_search(query: str, max_results: int = 5) -> dict:
    """Fallback: construct direct documentation URLs based on query keywords."""
    # Map common service keywords to doc URLs
    service_docs = {
        "lambda": ("AWS Lambda", "https://docs.aws.amazon.com/lambda/latest/dg/welcome.html"),
        "ec2": ("Amazon EC2", "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/concepts.html"),
        "s3": ("Amazon S3", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html"),
        "rds": ("Amazon RDS", "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Welcome.html"),
        "aurora": ("Amazon Aurora", "https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/CHAP_AuroraOverview.html"),
        "dynamodb": ("Amazon DynamoDB", "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Introduction.html"),
        "ecs": ("Amazon ECS", "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/Welcome.html"),
        "eks": ("Amazon EKS", "https://docs.aws.amazon.com/eks/latest/userguide/what-is-eks.html"),
        "vpc": ("Amazon VPC", "https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html"),
        "iam": ("AWS IAM", "https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html"),
        "cloudformation": ("AWS CloudFormation", "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/Welcome.html"),
        "cdk": ("AWS CDK", "https://docs.aws.amazon.com/cdk/v2/guide/home.html"),
        "bedrock": ("Amazon Bedrock", "https://docs.aws.amazon.com/bedrock/latest/userguide/what-is-bedrock.html"),
        "sagemaker": ("Amazon SageMaker", "https://docs.aws.amazon.com/sagemaker/latest/dg/whatis.html"),
        "step functions": ("AWS Step Functions", "https://docs.aws.amazon.com/step-functions/latest/dg/welcome.html"),
        "eventbridge": ("Amazon EventBridge", "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-what-is.html"),
        "sqs": ("Amazon SQS", "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/welcome.html"),
        "sns": ("Amazon SNS", "https://docs.aws.amazon.com/sns/latest/dg/welcome.html"),
        "api gateway": ("Amazon API Gateway", "https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html"),
        "cloudfront": ("Amazon CloudFront", "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Introduction.html"),
        "route 53": ("Amazon Route 53", "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/Welcome.html"),
        "elasticache": ("Amazon ElastiCache", "https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/WhatIs.html"),
        "neptune": ("Amazon Neptune", "https://docs.aws.amazon.com/neptune/latest/userguide/intro.html"),
        "kms": ("AWS KMS", "https://docs.aws.amazon.com/kms/latest/developerguide/overview.html"),
        "secrets manager": ("AWS Secrets Manager", "https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html"),
        "guardduty": ("Amazon GuardDuty", "https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html"),
        "security hub": ("AWS Security Hub", "https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html"),
        "waf": ("AWS WAF", "https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html"),
        "transit gateway": ("AWS Transit Gateway", "https://docs.aws.amazon.com/vpc/latest/tgw/what-is-transit-gateway.html"),
        "direct connect": ("AWS Direct Connect", "https://docs.aws.amazon.com/directconnect/latest/UserGuide/Welcome.html"),
        "organizations": ("AWS Organizations", "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html"),
        "control tower": ("AWS Control Tower", "https://docs.aws.amazon.com/controltower/latest/userguide/what-is-control-tower.html"),
        "well-architected": ("AWS Well-Architected", "https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html"),
        "cost explorer": ("AWS Cost Explorer", "https://docs.aws.amazon.com/cost-management/latest/userguide/ce-what-is.html"),
        "savings plans": ("Savings Plans", "https://docs.aws.amazon.com/savingsplans/latest/userguide/what-is-savings-plans.html"),
        "glue": ("AWS Glue", "https://docs.aws.amazon.com/glue/latest/dg/what-is-glue.html"),
        "athena": ("Amazon Athena", "https://docs.aws.amazon.com/athena/latest/ug/what-is.html"),
        "redshift": ("Amazon Redshift", "https://docs.aws.amazon.com/redshift/latest/mgmt/welcome.html"),
        "kinesis": ("Amazon Kinesis", "https://docs.aws.amazon.com/streams/latest/dev/introduction.html"),
        "msk": ("Amazon MSK", "https://docs.aws.amazon.com/msk/latest/developerguide/what-is-msk.html"),
        "opensearch": ("Amazon OpenSearch", "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/what-is.html"),
        "fargate": ("AWS Fargate", "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/AWS_Fargate.html"),
        "codepipeline": ("AWS CodePipeline", "https://docs.aws.amazon.com/codepipeline/latest/userguide/welcome.html"),
        "codebuild": ("AWS CodeBuild", "https://docs.aws.amazon.com/codebuild/latest/userguide/welcome.html"),
    }

    query_lower = query.lower()
    results = []
    for keyword, (name, url) in service_docs.items():
        if keyword in query_lower:
            results.append({
                "title": f"{name} Documentation",
                "snippet": f"Official AWS documentation for {name}. Search for '{query}' in the user guide.",
                "url": url,
                "service": name,
            })
            if len(results) >= max_results:
                break

    if not results:
        # Generic search URL
        encoded = quote_plus(query)
        results.append({
            "title": f"AWS Documentation Search: {query}",
            "snippet": f"Search AWS documentation for '{query}'",
            "url": f"https://docs.aws.amazon.com/search/doc-search.html?searchQuery={encoded}",
        })

    return {"query": query, "source": "AWS Documentation (fallback)", "results": results}


def _fallback_blog_search(query: str, max_results: int = 5) -> dict:
    """Fallback: construct AWS blog search URL."""
    encoded = quote_plus(query)
    return {
        "query": query,
        "source": "AWS Blog (fallback)",
        "results": [{
            "title": f"AWS Blog Search: {query}",
            "snippet": f"Search the AWS Blog for '{query}' — visit the link for latest posts.",
            "url": f"https://aws.amazon.com/blogs/?awsf.blog-master-category=*all&awsf.blog-master-learning-levels=*all&awsf.blog-master-industry=*all&awsf.blog-master-analytics-702702=*all&searchQuery={encoded}",
        }],
    }


def _clean_html(text: str) -> str:
    """Strip HTML tags and unescape entities."""
    if not text:
        return ""
    clean = re.sub(r'<[^>]+>', '', text)
    clean = unescape(clean)
    return clean.strip()
