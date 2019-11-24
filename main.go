package main

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/go-macaron/binding"
	chart "github.com/wcharczuk/go-chart"
	"gopkg.in/macaron.v1"
	"html/template"
	"math/rand"
	"mime/multipart"
	"sort"
	"strconv"
)

var Analysises map[string]Analysis

type Analysis struct {
	Traces      []*TraceItem
	JitterStats []*JitterStat
	Stats       TraceStats
}

func main() {
	Analysises = make(map[string]Analysis)
	m := macaron.Classic()
	m.Use(macaron.Renderer())

	m.Get("/", func(ctx *macaron.Context) {
		ctx.HTML(200, "index")
	})

	m.Post("/", binding.MultipartForm(SubmitForm{}), func(ctx *macaron.Context,
		form SubmitForm, errs binding.Errors) {
		if len(errs) > 0 {
			ctx.PlainText(400, []byte(fmt.Sprintf("Form binding error: %s", errs)))
			return
		}
		f, err := form.File.Open()
		if err != nil {
			ctx.PlainText(400, []byte("File uploaded cannot be opened"))
			return
		}
		defer f.Close()
		buf := bufio.NewScanner(f)

		// TODO make sure this ID does not already exist
		analysisID := fmt.Sprint(rand.Intn(899999) + 100000)
		var trace []*TraceItem
		trace, err = GetTracesFromBuffer(buf)
		if err != nil {
			ctx.PlainText(400, []byte(fmt.Sprintf("Failed to parse file: %s", err)))
			return
		}
		Analysises[analysisID] = Analysis{
			Traces:      trace,
			JitterStats: CalculateJitters(trace),
			Stats:       CalculateStats(trace),
		}
		ctx.Redirect(fmt.Sprintf("/%s", analysisID))
	})
	m.Group("/:id", func() {
		m.Get("/", func(ctx *macaron.Context) {
			analysis, ok := Analysises[ctx.Params("id")]
			if !ok {
				ctx.PlainText(404, []byte("Analysis results does not exist"))
				return
			}
			ctx.Data["ID"] = ctx.Params("id")
			ctx.Data["Analysis"] = analysis
			ctx.HTML(200, "analysis")
		})
		m.Get("/:from/:to/:type", func(ctx *macaron.Context) {
			analysis, ok := Analysises[ctx.Params("id")]
			if !ok {
				ctx.PlainText(404, []byte("Analysis results does not exist"))
				return
			}
			var from, to int
			var pType string = ctx.Params("type")
			var err error

			from, err = strconv.Atoi(ctx.Params("from"))
			if err != nil {
				ctx.PlainText(400, []byte("Malformed request parameters"))
				return
			}
			to, err = strconv.Atoi(ctx.Params("to"))
			if err != nil {
				ctx.PlainText(400, []byte("Malformed request parameters"))
				return
			}

			var st *JitterStat = nil
			for _, stat := range analysis.JitterStats {
				if stat.FromNode == from && stat.ToNode == to && stat.PacketType == pType {
					st = stat
				}
			}
			if st == nil {
				ctx.PlainText(404, []byte("The jitter stat requested does not exist"))
				return
			}

			ctx.Data["ID"] = ctx.Params("id")
			ctx.Data["Stat"] = st

			var seqValues, jitterValues []float64

			for seq := range st.Jitter {
				seqValues = append(seqValues, float64(seq))
			}
			sort.Float64s(seqValues)

			for v := range seqValues {
				jitterValues = append(jitterValues, st.Jitter[v])
				//fmt.Printf("(%d - %f) ", v, st.Jitter[v])
			}
			//fmt.Println(jitterValues)

			graph := chart.Chart{
				YAxis: chart.YAxis{
					Range: &chart.ContinuousRange{
						Min: -0.5,
						Max: 0.5,
					},
				},
				Series: []chart.Series{
					chart.ContinuousSeries{
						XValues: seqValues,
						YValues: jitterValues,
					},
				},
			}

			var imgBuf bytes.Buffer
			err = graph.Render(chart.SVG, &imgBuf)
			if err != nil {
				ctx.PlainText(500, []byte(fmt.Sprintf("Failed to generate jitter graph: %s", err)))
				return
			}

			ctx.Data["Graph"] = template.HTML(imgBuf.String())

			ctx.HTML(200, "jitter")
		})
	})
	m.Run()
}

// SubmitForm holds the POST submission form for uploading the trace file.
type SubmitForm struct {
	File *multipart.FileHeader `form:"file" binding:"Required"`
}