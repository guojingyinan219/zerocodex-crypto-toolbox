<script setup lang="ts">
import { computed, ref } from 'vue'
import { ChevronRight } from '@lucide/vue'
import type { Asn1TreeNode } from '../types'

const props = defineProps<{ node: Asn1TreeNode; selected?: string; depth?: number }>()
const emit = defineEmits<{ select: [node: Asn1TreeNode] }>()
const open = ref((props.depth ?? 0) < 3)
const hasChildren = computed(() => props.node.children.length > 0)
</script>

<template>
  <li class="asn-node">
    <div class="asn-node-row" :class="{ selected: selected === node.id }">
      <button v-if="hasChildren" class="tree-toggle" type="button" :title="open ? '折叠' : '展开'" @click="open = !open">
        <ChevronRight :size="14" :class="{ rotated: open }" />
      </button>
      <span v-else class="tree-spacer" />
      <button class="asn-node-content" type="button" @click="emit('select', node)">
        <strong>{{ node.type }}</strong>
        <span class="asn-meta">@0x{{ node.offset.toString(16) }} · {{ node.length }} B</span>
        <span v-if="node.value" class="asn-value">{{ node.value }}</span>
      </button>
    </div>
    <ul v-if="open && hasChildren">
      <Asn1Node v-for="child in node.children" :key="child.id" :node="child" :selected="selected" :depth="(depth ?? 0) + 1" @select="emit('select', $event)" />
    </ul>
  </li>
</template>
