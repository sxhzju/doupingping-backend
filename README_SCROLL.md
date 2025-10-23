# douyinCrawler - chrome_devtools evaluate_script usage with scroll.js

## 使用场景
在浏览器当前页面内执行自动下滑（触发懒加载）。

## chrome_devtools - evaluate_script 完整命令示例（更新方案）
为了兼容页面对脚本滚动的限制，先在内容区域模拟一次点击，再通过 wheel 事件与顶层 window.scrollBy 联合触发滚动。随后再回退到 scrollTop 方案。

- 参数说明
  - function: 传入一段可执行的异步函数字符串，该函数在页面上下文中运行。

推荐片段：
```
async () => {
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));

  // 1) 模拟点击“筛选”元素下方一点的空白，避免误点视频
  const clickBelowFilter = () => {
    const els = Array.from(document.querySelectorAll('*')).filter(el => (el.textContent || '').includes('筛选'));
    const filterEl = els.find(el => el.offsetParent !== null) || document.body;
    const rect = filterEl.getBoundingClientRect();
    let x = Math.floor(rect.left + rect.width / 2);
    let y = Math.floor(rect.bottom + 10);
    y = Math.min(y, window.innerHeight - 2);
    let el = document.elementFromPoint(x, y) || document.body;
    const isLink = (node) => node && (node.tagName === 'A' || (node.closest && node.closest('a')));
    if (isLink(el)) {
      for (let dy = 5; dy <= 60; dy += 5) {
        const cand = document.elementFromPoint(x, Math.min(y + dy, window.innerHeight - 2));
        if (cand && !isLink(cand)) { el = cand; y = Math.min(y + dy, window.innerHeight - 2); break; }
      }
    }
    el.dispatchEvent(new MouseEvent('mousedown', { clientX: x, clientY: y, bubbles: true }));
    el.dispatchEvent(new MouseEvent('mouseup',   { clientX: x, clientY: y, bubbles: true }));
    el.dispatchEvent(new MouseEvent('click',     { clientX: x, clientY: y, bubbles: true }));
    if (typeof el.focus === 'function') { try { el.focus(); } catch {} }
    return { clicked: true, tag: el.tagName, cls: el.className, id: el.id, x, y };
  };

  const clickInfo = clickBelowFilter();
  await sleep(200);

  // 2) 组合 wheel + window.scrollBy 提升滚动成功率
  for (let i = 0; i < 12; i++) {
    const target = document.elementFromPoint(Math.floor(window.innerWidth/2), Math.floor(window.innerHeight/2));
    if (target) {
      const wheel = new WheelEvent('wheel', { deltaY: 1200, bubbles: true });
      target.dispatchEvent(wheel);
    }
    window.scrollBy({ top: Math.floor(window.innerHeight * 0.9), left: 0, behavior: 'auto' });
    await sleep(400);
    const docEl = document.scrollingElement || document.documentElement;
    docEl.scrollTop = docEl.scrollTop + 400;
    await sleep(200);
  }

  // 3) 可选：若页面存在内层容器，再用 scrollTop 连续下推
  const inner = Array.from(document.querySelectorAll('*')).filter(el => {
    const sh = el.scrollHeight, ch = el.clientHeight, oy = getComputedStyle(el).overflowY;
    return sh > ch + 20 && (oy === 'auto' || oy === 'scroll' || oy === 'overlay');
  }).sort((a,b) => (b.scrollHeight - b.clientHeight) - (a.scrollHeight - a.clientHeight))[0];
  if (inner) {
    for (let s = 0; s < 8; s++) {
      inner.scrollTop += Math.max(100, Math.floor(inner.clientHeight * 0.9));
      await sleep(300);
    }
  }

  const y = window.scrollY || (document.scrollingElement && document.scrollingElement.scrollTop) || 0;
  const h = document.documentElement.scrollHeight;
  const hasNoMore = Array.from(document.querySelectorAll('*')).some(el => el.textContent && (el.textContent.includes('没有更多了') || el.textContent.includes('暂时没有更多了')));
  return { clickInfo, y, h, hasNoMore };
}
```


返回示例：
```
{
  "targetTag": "DIV",
  "id": "",
  "classes": "child-route-container route-scroll-container ...",
  "initial": { "y": 0, "height": 3395, "ch": 801 },
  "final":   { "y": 2594, "height": 3395, "ch": 801 }
}
```