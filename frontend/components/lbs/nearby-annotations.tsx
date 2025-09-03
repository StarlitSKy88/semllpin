'use client';

import React, { useState, useEffect } from 'react';
import { useLBSStore } from '@/lib/stores/lbs-store';
import { lbsService } from '@/lib/services/lbs-service';
import { MapPin, Award, Navigation, RefreshCw, Filter, Search, ChevronDown, ChevronUp } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Skeleton } from '@/components/ui/skeleton';

interface NearbyAnnotationsProps {
  onAnnotationSelect?: (annotationId: string) => void;
  onNavigateToAnnotation?: (latitude: number, longitude: number) => void;
  maxItems?: number;
  showFilters?: boolean;
  className?: string;
}

type SortOption = 'distance' | 'reward' | 'recent';
type FilterOption = 'all' | 'claimable' | 'discovered';

export function NearbyAnnotations({
  onAnnotationSelect,
  onNavigateToAnnotation,
  maxItems = 10,
  showFilters = true,
  className = ''
}: NearbyAnnotationsProps) {
  const {
    currentLocation,
    nearbyAnnotations,
    isLoadingNearby,
    nearbyError,
    searchRadius,
    loadNearbyAnnotations,
    claimReward,
    clearNearbyError
  } = useLBSStore();

  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState<SortOption>('distance');
  const [filterBy, setFilterBy] = useState<FilterOption>('all');
  const [isFiltersOpen, setIsFiltersOpen] = useState(false);
  const [isClaimingReward, setIsClaimingReward] = useState<string | null>(null);

  useEffect(() => {
    if (currentLocation && nearbyAnnotations.length === 0) {
      loadNearbyAnnotations();
    }
  }, [currentLocation]);

  const handleRefresh = () => {
    if (currentLocation) {
      loadNearbyAnnotations();
    }
  };

  const handleClaimReward = async (annotationId: string) => {
    setIsClaimingReward(annotationId);
    try {
      await claimReward(annotationId);
    } finally {
      setIsClaimingReward(null);
    }
  };

  const handleNavigate = (annotation: any) => {
    if (onNavigateToAnnotation) {
      onNavigateToAnnotation(annotation.location.latitude, annotation.location.longitude);
    }
  };

  const formatDistance = (meters: number) => {
    return lbsService.formatDistance(meters);
  };

  // 过滤和排序逻辑
  const filteredAndSortedAnnotations = React.useMemo(() => {
    let filtered = nearbyAnnotations;

    // 搜索过滤
    if (searchTerm) {
      filtered = filtered.filter(annotation =>
        annotation.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
        annotation.description.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    // 状态过滤
    switch (filterBy) {
      case 'claimable':
        filtered = filtered.filter(annotation => annotation.canClaim && !annotation.isDiscovered);
        break;
      case 'discovered':
        filtered = filtered.filter(annotation => annotation.isDiscovered);
        break;
      default:
        break;
    }

    // 排序
    switch (sortBy) {
      case 'distance':
        filtered.sort((a, b) => a.distance - b.distance);
        break;
      case 'reward':
        filtered.sort((a, b) => b.rewardAmount - a.rewardAmount);
        break;
      case 'recent':
        // 模拟按创建时间排序（实际应该从API获取）
        filtered.sort((a, b) => a.id.localeCompare(b.id));
        break;
    }

    return filtered.slice(0, maxItems);
  }, [nearbyAnnotations, searchTerm, filterBy, sortBy, maxItems]);

  const getStatusBadge = (annotation: any) => {
    if (annotation.isDiscovered) {
      return <Badge variant="secondary">已发现</Badge>;
    }
    if (annotation.canClaim) {
      return <Badge variant="default">可领取</Badge>;
    }
    return <Badge variant="outline">不可领取</Badge>;
  };

  const getDistanceColor = (distance: number) => {
    if (distance <= 100) return 'text-green-600';
    if (distance <= 500) return 'text-yellow-600';
    return 'text-gray-600';
  };

  if (!currentLocation) {
    return (
      <Card className={className}>
        <CardContent className="flex items-center justify-center py-8">
          <div className="text-center text-gray-500">
            <MapPin className="h-8 w-8 mx-auto mb-2 opacity-50" />
            <p>请先获取当前位置</p>
            <p className="text-xs">才能查看附近的标注</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className={className}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg font-semibold flex items-center gap-2">
            <Award className="h-5 w-5" />
            附近标注
            <Badge variant="outline">{filteredAndSortedAnnotations.length}</Badge>
          </CardTitle>
          <div className="flex items-center gap-2">
            {showFilters && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setIsFiltersOpen(!isFiltersOpen)}
              >
                <Filter className="h-4 w-4" />
              </Button>
            )}
            <Button
              variant="ghost"
              size="sm"
              onClick={handleRefresh}
              disabled={isLoadingNearby}
            >
              <RefreshCw className={`h-4 w-4 ${isLoadingNearby ? 'animate-spin' : ''}`} />
            </Button>
          </div>
        </div>
        
        {nearbyError && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-3 flex items-center justify-between">
            <span className="text-red-700 text-sm">{nearbyError}</span>
            <Button
              variant="ghost"
              size="sm"
              onClick={clearNearbyError}
            >
              ×
            </Button>
          </div>
        )}
      </CardHeader>

      <CardContent className="space-y-4">
        {/* 过滤器 */}
        {showFilters && (
          <Collapsible open={isFiltersOpen} onOpenChange={setIsFiltersOpen}>
            <CollapsibleTrigger asChild>
              <Button variant="ghost" className="w-full justify-between">
                <span className="flex items-center gap-2">
                  <Filter className="h-4 w-4" />
                  筛选和排序
                </span>
                {isFiltersOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </Button>
            </CollapsibleTrigger>
            <CollapsibleContent className="space-y-3 pt-3">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <Input
                  placeholder="搜索标注..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>
              
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-medium text-gray-500 mb-1 block">排序方式</label>
                  <Select value={sortBy} onValueChange={(value: SortOption) => setSortBy(value)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="distance">按距离</SelectItem>
                      <SelectItem value="reward">按奖励</SelectItem>
                      <SelectItem value="recent">按时间</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                
                <div>
                  <label className="text-xs font-medium text-gray-500 mb-1 block">状态筛选</label>
                  <Select value={filterBy} onValueChange={(value: FilterOption) => setFilterBy(value)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">全部</SelectItem>
                      <SelectItem value="claimable">可领取</SelectItem>
                      <SelectItem value="discovered">已发现</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </CollapsibleContent>
          </Collapsible>
        )}

        {/* 标注列表 */}
        <div className="space-y-3">
          {isLoadingNearby ? (
            // 加载骨架屏
            Array.from({ length: 3 }).map((_, index) => (
              <div key={index} className="border rounded-lg p-4">
                <div className="flex items-start justify-between">
                  <div className="flex-1 space-y-2">
                    <Skeleton className="h-4 w-3/4" />
                    <Skeleton className="h-3 w-full" />
                    <div className="flex gap-2">
                      <Skeleton className="h-5 w-16" />
                      <Skeleton className="h-5 w-16" />
                    </div>
                  </div>
                  <Skeleton className="h-8 w-20" />
                </div>
              </div>
            ))
          ) : filteredAndSortedAnnotations.length === 0 ? (
            <div className="text-center text-gray-500 py-8">
              <Award className="h-12 w-12 mx-auto mb-3 opacity-30" />
              <p className="font-medium">没有找到标注</p>
              <p className="text-sm">
                {searchTerm || filterBy !== 'all' 
                  ? '尝试调整搜索条件或筛选器'
                  : `在 ${formatDistance(searchRadius)} 范围内暂无标注`
                }
              </p>
            </div>
          ) : (
            filteredAndSortedAnnotations.map((annotation) => (
              <div
                key={annotation.id}
                className="border rounded-lg p-4 hover:bg-gray-50 transition-colors cursor-pointer"
                onClick={() => onAnnotationSelect?.(annotation.id)}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-2">
                      <h3 className="font-medium text-sm truncate">{annotation.title}</h3>
                      {getStatusBadge(annotation)}
                    </div>
                    
                    <p className="text-xs text-gray-600 mb-3 line-clamp-2">
                      {annotation.description}
                    </p>
                    
                    <div className="flex items-center gap-4 text-xs">
                      <span className={`flex items-center gap-1 ${getDistanceColor(annotation.distance)}`}>
                        <MapPin className="h-3 w-3" />
                        {formatDistance(annotation.distance)}
                      </span>
                      <span className="flex items-center gap-1 text-green-600">
                        <Award className="h-3 w-3" />
                        ¥{annotation.rewardAmount}
                      </span>
                    </div>
                  </div>
                  
                  <div className="flex flex-col gap-2 ml-3">
                    {annotation.canClaim && !annotation.isDiscovered && (
                      <Button
                        size="sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleClaimReward(annotation.id);
                        }}
                        disabled={isClaimingReward === annotation.id}
                        className="text-xs"
                      >
                        {isClaimingReward === annotation.id ? '领取中...' : '领取奖励'}
                      </Button>
                    )}
                    
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleNavigate(annotation);
                      }}
                      className="text-xs"
                    >
                      <Navigation className="h-3 w-3 mr-1" />
                      导航
                    </Button>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
        
        {/* 显示更多提示 */}
        {nearbyAnnotations.length > maxItems && (
          <div className="text-center text-xs text-gray-500 pt-2 border-t">
            显示前 {maxItems} 个结果，共 {nearbyAnnotations.length} 个标注
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default NearbyAnnotations;