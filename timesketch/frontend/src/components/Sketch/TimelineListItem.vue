<!--
Copyright 2019 Google Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->
<template>

  <div>

    <!-- Timeline detail modal -->
    <b-modal :active.sync="showInfoModal" :width="1024" scroll="keep">
      <div class="modal-background"></div>
      <div class="modal-content">
        <div class="card">
          <header class="card-header">
            <p class="card-header-title">Detailed information for {{ timeline.name }}</p>
          </header>
          <div class="card-content">
            <div class="content">
              <ul>
                <li>Elasticsearch index: {{ timeline.searchindex.index_name }}</li>
                <li v-if="meta.stats[timeline.searchindex.index_name]">Number of events: {{ meta.stats[timeline.searchindex.index_name]['count'] | compactNumber }} ({{ meta.stats[timeline.searchindex.index_name]['count']}})</li>
                <li v-if="meta.stats[timeline.searchindex.index_name]">Size on disk: {{ meta.stats[timeline.searchindex.index_name]['bytes'] | compactBytes }} ({{ meta.stats[timeline.searchindex.index_name]['bytes']}})</li>
                <li>Original name: {{ timeline.searchindex.name }}</li>
                <li>Added by: {{ timeline.searchindex.user.username }}</li>
                <li>Added: {{ timeline.searchindex.created_at | moment("YYYY-MM-DD HH:mm") }}</li>
              </ul>

              <span v-if="timelineStatus === 'fail'">
                <h5 style="color:red;">Error detail</h5>
                <pre>{{ timeline.searchindex.description }}</pre>
              </span>

            </div>
          </div>
        </div>
      </div>
      <button class="modal-close is-large" aria-label="close" v-on:click="showInfoModal = !showInfoModal"></button>
    </b-modal>

    <!-- Timeline edit modal -->
    <b-modal :active.sync="showEditModal" :width="640" scroll="keep">
      <div class="modal-background"></div>
      <div class="modal-content">
        <div class="card">
          <header class="card-header">
            <p class="card-header-title">Rename timeline</p>
          </header>
          <div class="card-content">
            <div class="content">
              <form v-on:submit.prevent="saveTimeline">
                <div class="field">
                  <div class="control">
                    <input v-model="timeline.name" class="input" type="text" required autofocus>
                  </div>
                </div>
                <div class="field">
                  <div class="control">
                    <input class="button is-success" type="submit" value="Save">
                  </div>
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>
      <button class="modal-close is-large" aria-label="close" v-on:click="showEditModal = !showEditModal"></button>
    </b-modal>

    <div v-if="timelineStatus === 'processing'" class="ts-timeline-color-box is-pulled-left blink" style="background-color: #f5f5f5;"></div>
    <div v-else-if="timelineStatus === 'fail'" v-on:click="showInfoModal =! showInfoModal" class="ts-timeline-color-box is-pulled-left" style="background-color: #f5f5f5;"></div>
    <div v-else-if="timelineStatus === 'ready'" class="dropdown is-pulled-left" v-bind:class="{'is-active': colorPickerActive}">
      <div class="dropdown-trigger">
        <div class="ts-timeline-color-box" v-bind:style="timelineColorStyle" v-on:click="colorPickerActive = !colorPickerActive"></div>
      </div>
      <div class="dropdown-menu" id="dropdown-menu" role="menu">
        <div class="dropdown-content" style="padding:0;">
          <div class="dropdown-item" style="padding:0;">
            <color-picker v-model="initialColor" @input="updateColor"></color-picker>
          </div>
        </div>
      </div>
    </div>
    <div v-else class="ts-timeline-color-box is-pulled-left" style="background-color: #f5f5f5;"></div>


    <div v-if="controls" class="field is-grouped is-pulled-right" style="margin-top:10px;">
      <p v-if="!isCompact" class="control">
        <button class="button is-rounded is-small is-outlined" v-on:click="showInfoModal = !showInfoModal">
                <span class="icon is-small">
                  <i class="fas fa-info-circle"></i>
                </span>
          <span>Info</span>
        </button>
      </p>
      <p v-if="meta.permissions.write && timelineStatus === 'ready' && !isCompact" class="control">
        <button class="button is-rounded is-small is-outlined" v-on:click="showEditModal = !showEditModal">
          <span class="icon is-small">
            <i class="fas fa-edit"></i>
          </span>
          <span>Rename</span>
        </button>
      </p>
      <p v-if="timelineStatus === 'ready'" class="control">
        <ts-analyzer-list-dropdown :timeline="timeline" @newAnalysisSession="setAnalysisSession($event)"></ts-analyzer-list-dropdown>
      </p>
      <p v-if="timelineStatus === 'ready' && !isCompact" class="control">
        <button class="button is-small is-rounded is-outlined" @click="showAnalysisHistory = !showAnalysisHistory">
          <span class="icon is-small">
            <i class="fas fa-history"></i>
          </span>
          <span>History</span>
        </button>
      </p>
      <p v-if="meta.permissions.write && !isCompact" class="control">
        <button v-on:click="remove(timeline)" class="button is-small is-rounded is-danger is-outlined">Remove</button>
      </p>
    </div>

    <router-link v-if="timelineStatus === 'ready'" :to="{ name: 'SketchExplore', query: {index: timeline.searchindex.index_name}}"><strong>{{ timeline.name }}</strong></router-link>
    <strong v-if="timelineStatus !== 'ready'">{{ timeline.name }}</strong>
    <br>

    <span v-if="timelineStatus === 'ready'" class="is-size-7">
      Added {{ timeline.updated_at | moment("YYYY-MM-DD HH:mm") }}
      <span class="tag is-small" :title="meta.stats[timeline.searchindex.index_name]['count'] + ' events in index'">{{ meta.stats[timeline.searchindex.index_name]['count'] | compactNumber }}</span>
    </span>
    <span v-else-if="timelineStatus === 'fail'" class="is-size-7">
      ERROR: <span v-on:click="showInfoModal =! showInfoModal" style="cursor:pointer;text-decoration: underline">Click here for details</span>
    </span>
    <span v-else-if="timelineStatus === 'processing'" class="is-size-7">
      Indexing in progress...
    </span>
    <span v-else class="is-size-7">
      Unknown status: {{ timelineStatus }}
    </span>

    <br>

    <div v-show="showAnalysisDetail">
      <ts-analyzer-session-detail :timeline="timeline" :session-id="analysisSessionId" @closeDetail="showAnalysisDetail = false"></ts-analyzer-session-detail>
    </div>

    <div v-if="showAnalysisHistory">
      <ts-analyzer-history :timeline="timeline" @closeHistory="showAnalysisHistory = false"></ts-analyzer-history>
    </div>

  </div>
</template>

<script>
import Vue from 'vue'
import { Chrome } from 'vue-color'
import _ from 'lodash'

import ApiClient from '../../utils/RestApiClient'

import TsAnalyzerListDropdown from './AnalyzerListDropdown'
import TsAnalyzerSessionDetail from './AnalyzerSessionDetail'
import TsAnalyzerHistory from './AnalyzerHistory'

export default {
  components: {
    'color-picker': Chrome,
    TsAnalyzerListDropdown,
    TsAnalyzerSessionDetail,
    TsAnalyzerHistory
  },
  props: ['timeline', 'controls', 'isCompact'],
  data () {
    return {
      initialColor: {},
      newColor: '',
      newTimelineName: '',
      colorPickerActive: false,
      showInfoModal: false,
      showEditModal: false,
      analysisSessionId: false,
      showAnalysisDetail: false,
      showAnalysisHistory: false,
      timelineStatus: null,
      autoRefresh: false
    }
  },
  computed: {
    sketch () {
      return this.$store.state.sketch
    },
    meta () {
      return this.$store.state.meta
    },
    timelineColorStyle () {
      let hexColor = this.newColor || this.timeline.color
      if (!hexColor.startsWith('#')) {
        hexColor = '#' + hexColor
      }
      return {
        'background-color': hexColor
      }
    }
  },
  methods: {
    remove (timeline) {
      this.$emit('remove', timeline)
    },
    updateColor: _.debounce(function (color) {
      this.newColor = color.hex
      if (this.newColor.startsWith('#')) {
        this.newColor = this.newColor.substring(1)
      }
      Vue.set(this.timeline, 'color', this.newColor)
      this.$emit('save', this.timeline)
    }, 300),
    saveTimeline () {
      this.showEditModal = false
      this.$emit('save', this.timeline)
    },
    setAnalysisSession (sessionId) {
      this.analysisSessionId = sessionId
      this.showAnalysisDetail = true
    },
    fetchData () {
      ApiClient.getSketchTimeline(this.sketch.id, this.timeline.id).then((response) => {
        this.timelineStatus = response.data.objects[0].searchindex.status[0].status
        if (this.timelineStatus !== 'ready') {
          this.autoRefresh = true
        }
        this.$store.dispatch('updateSketch', this.$store.state.sketch.id)
      }).catch((e) => {})
    }
  },
  mounted () {
    // Hide color picket when clicked outside.
    let self = this
    window.addEventListener('click', function (e) {
      if (!self.$el.contains(e.target)) {
        self.colorPickerActive = false
      }
    })
  },
  created () {
    this.initialColor = {
      hex: this.timeline.color
    }
    this.timelineStatus = this.timeline.searchindex.status[0].status
    if (this.timelineStatus !== 'ready') {
      this.autoRefresh = true
    }
  },
  beforeDestroy() {
    clearInterval(this.t)
    this.t = false
  },
  watch: {
    autoRefresh (val) {
      if (val && !this.t) {
        this.t = setInterval(function () {
          this.fetchData()
          if (this.timelineStatus === 'ready') {
            this.autoRefresh = false
          }
        }.bind(this), 5000)}
      else {
        clearInterval(this.t)
        this.t = false
      }
    }
  }
}
</script>

<!-- CSS scoped to this component only -->
<style scoped lang="scss">
.list-item {
  display: inline-block;
  margin-right: 10px;
}
.list-enter-active, .list-leave-active {
  transition: all 0.5s;
}
.list-enter, .list-leave-to {
  opacity: 0;
  transform: translateY(30px);
}
.vc-sketch {
  box-shadow: none;
}

.blink {
  animation: blinker 1s linear infinite;
}

@keyframes blinker {
  50% {
    opacity: 40%;
  }
}
</style>
